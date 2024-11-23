//lib.rs
#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use num_bigint::{BigUint, BigInt, Sign};
use num_traits::Zero;
pub mod opcodes;
pub mod u256;
mod types;
use types::{Address, H256};
use crate::opcodes::{
  COLD_SLOAD_COST,
  WARM_STORAGE_READ_COST,
  COLD_ACCOUNT_ACCESS_COST,
  WARM_ACCOUNT_ACCESS_COST,
  GMEMORY,
  GQUADRATICMEMDENOM,
  GCOPY,
  GEXPONENTBYTE,
  EXP_SUPPLEMENTAL_GAS,
};

// Track accessed addresses and storage slots for EIP-2929
#[derive(Default)]
pub struct AccessList {
    addresses: HashSet<Address>,
    storage: HashMap<Address, HashSet<H256>>,
}
impl AccessList {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn is_storage_cold(&self, address: &Address, slot: &H256) -> bool {
      self.is_cold_slot(address, slot)
    }
    pub fn mark_storage_warm(&mut self, address: Address, slot: H256) {
        self.mark_slot_warm(address, slot);
    }
    pub fn is_cold_address(&self, address: &Address) -> bool {
        !self.addresses.contains(address)
    }
    pub fn is_cold_slot(&self, address: &Address, slot: &H256) -> bool {
        !self.storage
            .get(address)
            .map_or(false, |slots| slots.contains(slot))
    }
    pub fn mark_address_warm(&mut self, address: Address) {
        self.addresses.insert(address);
    }
    pub fn mark_slot_warm(&mut self, address: Address, slot: H256) {
        self.storage.entry(address).or_default().insert(slot);
    }
}

#[derive(Default)]
pub struct Stack {
    pub pc: usize,
    pub calldata_i: usize,
    pub calldata_size: usize,
    pub stack: Vec<[u8; 32]>,
    pub storage_committed: HashMap<[u8; 32], Vec<u8>>,
    pub storage: HashMap<[u8; 32], Vec<u8>>,
    pub mem: Vec<u8>,
    pub gas: u64,
    pub refund: i64,  // Track gas refunds for EIP-3529
    pub opcodes: HashMap<u8, opcodes::Opcode>,
    pub current_address: Address,  // Track current contract address
    pub access_list: AccessList,   // Track accessed addresses and slots
    pub code: Vec<u8>,
}

impl Stack {
    pub fn new() -> Stack {
        let mut s = Stack {
            pc: 0,
            calldata_i: 0,
            calldata_size: 32,
            stack: Vec::new(),
            storage_committed: HashMap::new(),
            storage: HashMap::new(),
            mem: Vec::new(),
            gas: 10000000000,
            refund: 0,
            opcodes: HashMap::new(),
            current_address: [0u8; 20],
            access_list: AccessList::new(),
            code: Vec::new(),
        };
        s.opcodes = opcodes::new_opcodes();
        s
    }
    pub fn print_stack(&self) {
        println!("stack ({}):", self.stack.len());
        for i in (0..self.stack.len()).rev() {
            println!("{:?}", vec_u8_to_hex(self.stack[i].to_vec()));
        }
    }
    pub fn print_memory(&self) {
        if !self.mem.is_empty() {
            println!("memory ({}):", self.mem.len());
            println!("{:?}", vec_u8_to_hex(self.mem.to_vec()));
        }
    }
    pub fn print_storage(&self) {
        if !self.storage.is_empty() {
            println!("storage ({}):", self.storage.len());
            for (key, value) in self.storage.iter() {
                println!(
                    "{:?}: {:?}",
                    vec_u8_to_hex(key.to_vec()),
                    vec_u8_to_hex(value.to_vec())
                );
            }
        }
    }
    // Pushes an arbitrary length byte slice onto the stack
    // Pads with leading zeros to make it 32 bytes
    // Used by PUSH1-PUSH32 operations
    pub fn push_arbitrary(&mut self, b: &[u8]) {
        // TODO if b.len()>32 return error
        let mut d: [u8; 32] = [0; 32]; // Create zero-filled 32-byte array
        // Copy input bytes to end of array
        // Example: for 1 byte input 0x12
        // d becomes: [0,0,0,...,0,0x12]
        d[32 - b.len()..].copy_from_slice(b);
        self.stack.push(d);
    }
    // Pushes a full 32-byte array onto the stack
    // Converts the input [u8; 32] array to H256 type before pushing
    pub fn push(&mut self, value: [u8; 32]) {
      self.stack.push(H256::from(value));
    }
    // put_arbitrary puts in the last element of the stack the value
    pub fn put_arbitrary(&mut self, b: &[u8]) {
        // TODO if b.len()>32 return error
        let mut d: [u8; 32] = [0; 32];
        d[0..b.len()].copy_from_slice(b); // put without left padding
        let l = self.stack.len();
        self.stack[l - 1] = d;
    }

    pub fn pop(&mut self) -> Result<[u8; 32], String> {
        self.stack.pop()
            .map(|h| h.into())
            .ok_or_else(|| "The stack is empty".to_string())
    }
    // `peek()` looks at top of stack without removing the value
    pub fn peek(&mut self) -> Result<[u8; 32], String> {
        if self.stack.is_empty() {
            return Err("peek err".to_string());
        }
        Ok(self.stack[self.stack.len() - 1])
    }

    // EXTCODESIZE (0x3b)
    pub fn extcodesize(&mut self) -> Result<(), String> {
        let mut address: Address = [0u8; 20];
        address.copy_from_slice(&self.pop()?[12..32]);

        // Apply EIP-2929 access cost
        let access_cost = if self.access_list.is_cold_address(&address) {
            self.access_list.mark_address_warm(address);
            COLD_ACCOUNT_ACCESS_COST
        } else {
            WARM_ACCOUNT_ACCESS_COST
        };
        self.gas -= access_cost;

        // TODO: In a real implementation, you'd get the code size of the address
        // For now, just pushing 0
        self.push(u256::usize_to_u256(0));
        Ok(())
    }
    // EXTCODECOPY (0x3c)
    pub fn extcodecopy(&mut self) -> Result<(), String> {
        let mut address: Address = [0u8; 20];
        address.copy_from_slice(&self.pop()?[12..32]);
        let dest_offset = u256::u256_to_u64(self.pop()?) as usize;
        let offset = u256::u256_to_u64(self.pop()?) as usize;
        let length = u256::u256_to_u64(self.pop()?) as usize;

        // Apply EIP-2929 access cost
        let access_cost = if self.access_list.is_cold_address(&address) {
        self.access_list.mark_address_warm(address);
        opcodes::COLD_ACCOUNT_ACCESS_COST
      } else {
          opcodes::WARM_ACCOUNT_ACCESS_COST
      };
      self.gas -= access_cost;

      self.extend_mem(dest_offset, length);
      self.spend_gas_data_copy(length);

      // Zero memory for now
      for i in 0..length {
          self.mem[dest_offset + i] = 0;
      }

      Ok(())
    }

    // EXTCODEHASH (0x3f)
    pub fn extcodehash(&mut self) -> Result<(), String> {
        let mut address: Address = [0u8; 20];
        address.copy_from_slice(&self.pop()?[12..32]);

        let access_cost = if self.access_list.is_cold_address(&address) {
            self.access_list.mark_address_warm(address);
            opcodes::COLD_ACCOUNT_ACCESS_COST
        } else {
            opcodes::WARM_ACCOUNT_ACCESS_COST
        };
        self.gas -= access_cost;

        self.push([0u8; 32]);
        Ok(())
    }

    // CALL (0xf1)
    pub fn call(&mut self) -> Result<(), String> {
        let gas = u256::u256_to_u64(self.pop()?);
        let mut address: Address = [0u8; 20];
        address.copy_from_slice(&self.pop()?[12..32]);
        let value = self.pop()?;
        let args_offset = u256::u256_to_u64(self.pop()?) as usize;
        let args_length = u256::u256_to_u64(self.pop()?) as usize;
        let ret_offset = u256::u256_to_u64(self.pop()?) as usize;
        let ret_length = u256::u256_to_u64(self.pop()?) as usize;

        let access_cost = if self.access_list.is_cold_address(&address) {
            self.access_list.mark_address_warm(address);
            opcodes::COLD_ACCOUNT_ACCESS_COST
        } else {
           opcodes::WARM_ACCOUNT_ACCESS_COST
        };
        self.gas -= access_cost;

        self.extend_mem(args_offset, args_length);
        self.extend_mem(ret_offset, ret_length);

        self.push(u256::usize_to_u256(1));
        Ok(())
    }

    // CALLCODE (0xf2)
    pub fn callcode(&mut self) -> Result<(), String> {
        let gas = u256::u256_to_u64(self.pop()?);
        let mut address: Address = [0u8; 20];
        address.copy_from_slice(&self.pop()?[12..32]);
        let value = self.pop()?;
        let args_offset = u256::u256_to_u64(self.pop()?) as usize;
        let args_length = u256::u256_to_u64(self.pop()?) as usize;
        let ret_offset = u256::u256_to_u64(self.pop()?) as usize;
        let ret_length = u256::u256_to_u64(self.pop()?) as usize;

        let access_cost = if self.access_list.is_cold_address(&address) {
            self.access_list.mark_address_warm(address);
            opcodes::COLD_ACCOUNT_ACCESS_COST
        } else {
            opcodes::WARM_ACCOUNT_ACCESS_COST
        };
        self.gas -= access_cost;

        self.extend_mem(args_offset, args_length);
        self.extend_mem(ret_offset, ret_length);

        self.push(u256::usize_to_u256(1));
        Ok(())
    }

    // DELEGATECALL (0xf4)
    pub fn delegatecall(&mut self) -> Result<(), String> {
        let gas = u256::u256_to_u64(self.pop()?);
        let mut address: Address = [0u8; 20];
        address.copy_from_slice(&self.pop()?[12..32]);
        let args_offset = u256::u256_to_u64(self.pop()?) as usize;
        let args_length = u256::u256_to_u64(self.pop()?) as usize;
        let ret_offset = u256::u256_to_u64(self.pop()?) as usize;
        let ret_length = u256::u256_to_u64(self.pop()?) as usize;

        let access_cost = if self.access_list.is_cold_address(&address) {
            self.access_list.mark_address_warm(address);
            opcodes::COLD_ACCOUNT_ACCESS_COST
        } else {
            opcodes::WARM_ACCOUNT_ACCESS_COST
        };
        self.gas -= access_cost;

        self.extend_mem(args_offset, args_length);
        self.extend_mem(ret_offset, ret_length);

        self.push(u256::usize_to_u256(1));
        Ok(())
    }



    // Handle cold/warm access for account accessing operations to handle EIP-2929 and EIP-3529
    fn charge_account_access(&mut self, access_list: &mut AccessList, address: &Address) -> u64 {
        if access_list.is_cold_address(address) {
            access_list.mark_address_warm(address.clone());
            COLD_ACCOUNT_ACCESS_COST
        } else {
            WARM_ACCOUNT_ACCESS_COST
        }
    }
    // EIP-2929: Handle SLOAD with cold/warm access
    pub fn sload(&mut self) -> Result<(), String> {
        let address = self.current_address;
        let mut slot: H256 = [0u8; 32];
        slot.copy_from_slice(&self.pop()?[..]);

        let access_cost = if self.access_list.is_cold_slot(&address, &slot) {
            self.access_list.mark_slot_warm(address, slot.clone());
            COLD_SLOAD_COST
        } else {
            WARM_STORAGE_READ_COST
        };

        self.gas -= access_cost;

        let value = self.storage.get(&slot).cloned().unwrap_or_default();
        self.push_arbitrary(&value);

        Ok(())
    }

    pub fn balance(&mut self) -> Result<(), String> {
        let mut address: Address = [0u8; 20];
        address.copy_from_slice(&self.pop()?[12..32]);

        let access_cost = if self.access_list.is_cold_address(&address) {
            self.access_list.mark_address_warm(address);
            COLD_ACCOUNT_ACCESS_COST
        } else {
              WARM_ACCOUNT_ACCESS_COST
        };

        self.gas -= access_cost;
        Ok(())
  }

    // Add stack underflow validation helper
    fn require_stack_items(&self, required: usize) -> Result<(), String> {
        if self.stack.len() < required {
            return Err(format!("stack underflow: need {} items but have {}",
            required, self.stack.len()));
        }
        Ok(())
    }
    // arithmetic operations
    pub fn add(&mut self) -> Result<(), String> {
        self.require_stack_items(2)?;
        let b0 = BigUint::from_bytes_be(&self.pop()?[..]);
        let b1 = BigUint::from_bytes_be(&self.pop()?[..]);
        self.push_arbitrary(&(b0 + b1).to_bytes_be());
        Ok(())
    }
    pub fn mul(&mut self) -> Result<(), String> {
        let b0 = BigUint::from_bytes_be(&self.pop()?[..]);
        let b1 = BigUint::from_bytes_be(&self.pop()?[..]);
        self.push_arbitrary(&(b0 * b1).to_bytes_be());
        Ok(())
    }
    pub fn sub(&mut self) -> Result<(), String> {
        let b0 = BigUint::from_bytes_be(&self.pop()?[..]);
        let b1 = BigUint::from_bytes_be(&self.pop()?[..]);
        if b0 >= b1 {
            self.push_arbitrary(&(b0 - b1).to_bytes_be());
        } else {
            // 2**256 TODO this will not be here hardcoded, there will be a custom type uint256
            let max =
                "115792089237316195423570985008687907853269984665640564039457584007913129639936"
                    .parse::<BigUint>()
                    .unwrap();
            self.push_arbitrary(&(max + b0 - b1).to_bytes_be());
        }
        Ok(())
    }
    pub fn div(&mut self) -> Result<(), String> {
        self.require_stack_items(2)?;
        let b0 = BigUint::from_bytes_be(&self.pop()?[..]);
        let b1 = BigUint::from_bytes_be(&self.pop()?[..]);
        self.push_arbitrary(&(b0 / b1).to_bytes_be());
        Ok(())
    }
    pub fn sdiv(&mut self) -> Result<(), String> {
        let b0 = BigInt::from_bytes_be(Sign::Plus, &self.pop()?[..]);
        let b1 = BigInt::from_bytes_be(Sign::Plus, &self.pop()?[..]);

        if b1.is_zero() {
            self.push_arbitrary(&[0u8; 32]);
            return Ok(());
        }

        let result = b0 / b1;
        self.push_arbitrary(&result.to_bytes_be().1);
        Ok(())
    }
    pub fn modulus(&mut self) -> Result<(), String> {
        let b0 = BigUint::from_bytes_be(&self.pop()?[..]);
        let b1 = BigUint::from_bytes_be(&self.pop()?[..]);
        self.push_arbitrary(&(b0 % b1).to_bytes_be());
        Ok(())
    }
    pub fn smod(&mut self) -> Result<(), String> {
        Err("unimplemented".to_string())
    }
    pub fn add_mod(&mut self) -> Result<(), String> {
        let b0 = BigUint::from_bytes_be(&self.pop()?[..]);
        let b1 = BigUint::from_bytes_be(&self.pop()?[..]);
        let b2 = BigUint::from_bytes_be(&self.pop()?[..]);
        self.push_arbitrary(&(b0 + b1 % b2).to_bytes_be());
        Ok(())
    }
    pub fn mul_mod(&mut self) -> Result<(), String> {
        let b0 = BigUint::from_bytes_be(&self.pop()?[..]);
        let b1 = BigUint::from_bytes_be(&self.pop()?[..]);
        let b2 = BigUint::from_bytes_be(&self.pop()?[..]);
        self.push_arbitrary(&(b0 * b1 % b2).to_bytes_be());
        Ok(())
    }
    pub fn exp(&mut self) -> Result<(), String> {
        let b = BigUint::from_bytes_be(&self.pop()?[..]);
        let e = BigUint::from_bytes_be(&self.pop()?[..]);

        let mut r = "1".parse::<BigUint>().unwrap();
        let zero = "0".parse::<BigUint>().unwrap();
        let mut rem = e.clone();
        let mut exp = b;
        // 2**256 TODO this will not be here hardcoded, there will be a custom type uint256
        let field =
            "115792089237316195423570985008687907853269984665640564039457584007913129639936"
                .parse::<BigUint>()
                .unwrap();
        while rem != zero {
            if rem.bit(0) {
                // is odd
                r = r * exp.clone() % field.clone();
            }
            exp = exp.clone() * exp.clone();
            rem >>= 1;
        }
        self.push_arbitrary(&r.to_bytes_be());

        let n_bytes = &e.to_bytes_be().len();
        let mut exp_fee = (n_bytes * GEXPONENTBYTE as usize) as u64;
        exp_fee += (EXP_SUPPLEMENTAL_GAS as usize * n_bytes) as u64;
        self.gas -= exp_fee as u64;
        Ok(())
    }

    // boolean operations
    pub fn lt(&mut self) -> Result<(), String> {
        let a = BigUint::from_bytes_be(&self.pop()?[..]);
        let b = BigUint::from_bytes_be(&self.pop()?[..]);
        self.push(u256::usize_to_u256((a < b) as usize));
        Ok(())
    }
    pub fn gt(&mut self) -> Result<(), String> {
        let a = BigUint::from_bytes_be(&self.pop()?[..]);
        let b = BigUint::from_bytes_be(&self.pop()?[..]);
        self.push(u256::usize_to_u256((a > b) as usize));
        Ok(())
    }
    pub fn eq(&mut self) -> Result<(), String> {
        let a = BigUint::from_bytes_be(&self.pop()?[..]);
        let b = BigUint::from_bytes_be(&self.pop()?[..]);
        self.push(u256::usize_to_u256((a == b) as usize));
        Ok(())
    }
    pub fn is_zero(&mut self) -> Result<(), String> {
        let a = BigUint::from_bytes_be(&self.pop()?[..]);
        self.push(u256::usize_to_u256(a.is_zero() as usize));
        Ok(())
    }
    pub fn and(&mut self) -> Result<(), String> {
        let a = BigUint::from_bytes_be(&self.pop()?[..]);
        let b = BigUint::from_bytes_be(&self.pop()?[..]);
        self.push_arbitrary(&(a & b).to_bytes_be());
        Ok(())
    }
    pub fn or(&mut self) -> Result<(), String> {
        let a = BigUint::from_bytes_be(&self.pop()?[..]);
        let b = BigUint::from_bytes_be(&self.pop()?[..]);
        self.push_arbitrary(&(a | b).to_bytes_be());
        Ok(())
    }
    pub fn xor(&mut self) -> Result<(), String> {
        let a = BigUint::from_bytes_be(&self.pop()?[..]);
        let b = BigUint::from_bytes_be(&self.pop()?[..]);
        self.push_arbitrary(&(a ^ b).to_bytes_be());
        Ok(())
    }
    pub fn not(&mut self) -> Result<(), String> {
        // 2**256-1 TODO this will not be here hardcoded, there will be a custom type uint256
        let f = "115792089237316195423570985008687907853269984665640564039457584007913129639935"
            .parse::<BigUint>()
            .unwrap();

        let a = BigUint::from_bytes_be(&self.pop()?[..]);
        self.push_arbitrary(&(f - a).to_bytes_be());
        Ok(())
    }

    // contract context
    pub fn calldata_load(&mut self, calldata: &[u8]) -> Result<(), String> {
        let mut start = self.calldata_i;
        if !self.stack.is_empty() {
            start = u256::u256_to_u64(self.peek()?) as usize;
        }
        let l = calldata.len();
        if start > l {
            start = l;
        }
        let mut end = start + self.calldata_size;
        if end > l {
            end = l;
        }
        self.put_arbitrary(&calldata[start..end]);
        self.calldata_i += self.calldata_size;
        Ok(())
    }
    pub fn calldata_size(&mut self, calldata: &[u8]) {
        self.calldata_size = calldata.len();
        self.push(u256::usize_to_u256(self.calldata_size));
    }
    fn spend_gas_data_copy(&mut self, length: usize) {
        let length32 = upper_multiple_of_32(length);
        self.gas -= ((GCOPY as usize * length32) / 32) as u64;
    }
    pub fn code_copy(&mut self, code: &[u8]) -> Result<(), String> {
        let dest_offset = u256::u256_to_u64(self.pop()?) as usize;
        let offset = u256::u256_to_u64(self.pop()?) as usize;
        let length = u256::u256_to_u64(self.pop()?) as usize;

        self.extend_mem(dest_offset, length);
        self.spend_gas_data_copy(length);

        for i in 0..length {
            if offset + i < code.len() {
                self.mem[dest_offset + i] = code[offset + i];
            } else {
                self.mem[dest_offset + i] = 0;
            }
        }
        // self.mem[dest_offset..dest_offset+length] =
        Ok(())
    }


    // storage and execution
    pub fn extend_mem(&mut self, start: usize, size: usize) {
        // Skip if no expansion needed
        if size <= self.mem.len() || start + size <= self.mem.len() {
            return;
        }
        // Calculate sizes in 32-byte words
        let old_size = self.mem.len() / 32;
        let new_size = upper_multiple_of_32(start + size) / 32;
        // Calculate gas fees
        // Old fee = linear cost + quadratic cost
        let old_total_fee = (old_size * GMEMORY as usize + old_size.pow(2) / GQUADRATICMEMDENOM as usize) as u64;
        let new_total_fee = (new_size * GMEMORY as usize + new_size.pow(2) / GQUADRATICMEMDENOM as usize) as u64;
        let mem_fee = new_total_fee - old_total_fee;
        self.gas -= mem_fee as u64;
        let mut new_bytes: Vec<u8> = vec![0; (new_size - old_size) * 32];
        self.mem.append(&mut new_bytes);
    }
    pub fn mload(&mut self) -> Result<(), String> {
        let pos = u256::u256_to_u64(self.pop()?) as usize;
        self.extend_mem(pos as usize, 32);
        let mem32 = self.mem[pos..pos + 32].to_vec();
        self.push_arbitrary(&mem32);
        Ok(())
    }
    pub fn mstore(&mut self) -> Result<(), String> {
        let pos = u256::u256_to_u64(self.pop()?);
        let val = self.pop()?;
        self.extend_mem(pos as usize, 32);

        self.mem[pos as usize..].copy_from_slice(&val);
        Ok(())
    }


    pub fn jump(&mut self, code: &[u8]) -> Result<(), String> {
        // TODO that jump destination is valid
        let new_pc = u256::u256_to_u64(self.pop()?) as usize;
        if !valid_dest(code, new_pc) {
            return Err(format!("not valid dest: {:02x}", new_pc));
        }
        self.pc = new_pc;
        Ok(())
    }
    pub fn jump_i(&mut self, code: &[u8]) -> Result<(), String> {
        let new_pc = u256::u256_to_u64(self.pop()?) as usize;
        if !valid_dest(code, new_pc) {
            return Err(format!("not valid dest: {:02x}", new_pc));
        }
        if !self.stack.is_empty() {
            let cond = u256::u256_to_u64(self.pop()?) as usize;
            if cond != 0 {
                self.pc = new_pc;
            }
        }
        // let cont = self.pop();
        // if cont {} // TODO depends on having impl Err in pop()
        Ok(())
    }
    pub fn jump_dest(&mut self) -> Result<(), String> {
      if self.pc < self.code.len() {
          println!("Byte at pc: 0x{:02x}", self.code[self.pc]);
      }
      // Check bounds
      if self.pc >= self.code.len() {
          return Err("JUMPDEST: pc out of bounds".to_string());
      }
      // Check if current instruction is JUMPDEST (0x5b)
      if self.code[self.pc] != 0x5b {
          return Err(format!("Invalid JUMPDEST: found 0x{:02x} at position {}",
              self.code[self.pc], self.pc));
      }
      Ok(())
    }
    pub fn substract_gas(&mut self, value: u64) -> Result<(), String> {
        if self.gas < value {
            return Err("Out of gas".to_string());
        }
        self.gas -= value;
        Ok(())
    }
    pub fn execute(
        &mut self,
        code: &[u8],
        calldata: &[u8],
        debug: bool,
        ) -> Result<Vec<u8>, String> {
            self.pc = 0;
            self.calldata_i = 0;
            self.code = code.to_vec();
            let l = code.len();

            while self.pc < l {
                let opcode = code[self.pc];
                if !self.opcodes.contains_key(&opcode) {
                    return Err(format!("Invalid opcode {:x}", opcode));
                }

                if debug {
                    println!(
                        "{} (0x{:x}): pc={:?} gas={:?}",
                        self.opcodes.get(&opcode).unwrap().name,
                        opcode,
                        self.pc,
                        self.gas,
                    );
                    self.print_stack();
                    self.print_memory();
                    self.print_storage();
                    println!();
                }

                // Get base gas cost
                let base_gas = self.opcodes.get(&opcode).unwrap().gas;

                match opcode & 0xf0 /* the use of mask to match the pattern */ {
                    0x00 => {
                        // arithmetic operations
                        match opcode {
                            0x00 => {
                                println!("0x00: STOP");
                                return Ok(Vec::new());
                            }
                            0x01 => self.add()?,
                            0x02 => self.mul()?,
                            0x03 => self.sub()?,
                            0x04 => self.div()?,
                            0x05 => self.sdiv()?,
                            0x06 => self.modulus()?,
                            0x07 => self.smod()?,
                            0x08 => self.add_mod()?,
                            0x09 => self.mul_mod()?,
                            0x0a => self.exp()?,
                            _ => return Err(format!("unimplemented {:x}", opcode)),
                        }
                        self.pc += 1;
                    }
                    0x10 => {
                        // comparison operations
                        match opcode {
                            0x10 => self.lt()?,
                            0x11 => self.gt()?,
                            // 0x12 => self.slt()?,
                            // 0x13 => self.sgt()?,
                            0x14 => self.eq()?,
                            0x15 => self.is_zero()?,
                            0x16 => self.and()?,
                            0x17 => self.or()?,
                            0x18 => self.xor()?,
                            0x19 => self.not()?,
                            // 0x1a => self.byte()?,
                            _ => return Err(format!("unimplemented {:x}", opcode)),
                        }
                        self.pc += 1;
                    }
                    0x30 => {
                        match opcode {
                            0x31 => self.balance()?,
                            0x35 => self.calldata_load(&calldata)?,
                            0x36 => self.calldata_size(&calldata),
                            0x39 => self.code_copy(&code)?,
                            0x3b => self.extcodesize()?, // EXTCODESIZE with EIP-2929
                            0x3c => self.extcodecopy()?, // EXTCODECOPY with EIP-2929
                            0x3f => self.extcodehash()?, // EXTCODEHASH with EIP-2929
                            _ => return Err(format!("unimplemented {:x}", opcode)),
                        }
                        self.pc += 1;
                    }
                    0x50 => {
                        match opcode {
                            0x5b => self.jump_dest()?,  // Handle JUMPDEST first without PC increment
                            _ => {
                                self.pc += 1;  // Increment PC for all other 0x50 opcodes
                                match opcode {
                                    0x51 => self.mload()?,
                                    0x52 => self.mstore()?,
                                    0x54 => self.sload()?,
                                    0x55 => self.sstore()?,
                                    0x56 => self.jump(code)?,
                                    0x57 => self.jump_i(code)?,
                                    _ => return Err(format!("unimplemented {:x}", opcode)),
                                }
                            }
                        }
                        // Increment PC only for JUMPDEST after validation
                        if opcode == 0x5b {
                            self.pc += 1;
                        }
                    }
                    0x60 | 0x70 => {
                        // push operations
                        let n = (opcode - 0x5f) as usize; // depends on the number of PUSH{} args
                        self.push_arbitrary(&code[self.pc + 1..self.pc + 1 + n]);
                        self.pc += 1 + n;
                    }
                    0x80 => {
                        // dup
                        let l = self.stack.len();
                        if opcode > 0x7f {
                            self.stack.push(self.stack[l - (opcode - 0x7f) as usize]);
                        } else {
                            self.stack.push(self.stack[(0x7f - opcode) as usize]);
                        }
                        self.pc += 1;
                    }
                    0x90 => {
                        // 0x9x swap
                        let l = self.stack.len();
                        let pos;
                        if opcode > 0x8e {
                            pos = l - (opcode - 0x8e) as usize;
                        } else {
                            pos = (0x8e - opcode) as usize;
                        }
                        self.stack.swap(pos, l - 1);
                        self.pc += 1;
                    }
                    0xf0 => {
                        match opcode {
                            0xf1 => self.call()?, // CALL with EIP-2929
                            0xf2 => self.callcode()?, // CALLCODE with EIP-2929
                            0xf3 => {
                                let pos_to_return = u256::u256_to_u64(self.pop()?) as usize;
                                let len_to_return = u256::u256_to_u64(self.pop()?) as usize;
                                return Ok(self.mem[pos_to_return..pos_to_return + len_to_return].to_vec());
                            }
                            0xf4 => self.delegatecall()?, // DELEGATECALL with EIP-2929
                            _ => return Err(format!("unimplemented {:x}", opcode)),
                        }
                        self.pc += 1;
                    }
                    _ => {
                        return Err(format!("unimplemented {:x}", opcode));
                    }
                }
                self.substract_gas(base_gas)?;
            }
            Ok(Vec::new())
        }

    pub fn sstore(&mut self) -> Result<(), String> {
        let key: H256 = self.pop()?.into();
        let value = self.pop()?;

        // Check cold/warm access
        let access_cost = if self.access_list.is_storage_cold(&self.current_address, &key) {
            self.access_list.mark_storage_warm(self.current_address, key);
            opcodes::COLD_SLOAD_COST
        } else {
            opcodes::WARM_STORAGE_READ_COST
        };

        self.gas -= access_cost;

        let original = self.storage_committed.get(&key).cloned();
        let current = self.storage.get(&key).cloned();

        // Calculate gas and refund per EIP-3529
        let (gas_cost, refund) = self.calculate_sstore_gas_and_refund(
            &original,
            &current,
            &value.to_vec()
        );

          self.gas -= gas_cost;
          self.refund += refund;

          // Update storage
          if value.iter().all(|&x| x == 0) {
              self.storage.remove(&key);
          } else {
              self.storage.insert(key, value.to_vec());
          }
          Ok(())
      }

      // Helper for SSTORE gas calculation
      fn calculate_sstore_gas_and_refund(
          &self,
          original: &Option<Vec<u8>>,
          current: &Option<Vec<u8>>,
          new: &Vec<u8>
      ) -> (u64, i64) {
          let is_zero = |v: &Option<Vec<u8>>| v.as_ref().map_or(true, |x| x.iter().all(|&b| b == 0));

          // No-op case
          if current.as_ref().map(|v| v == new).unwrap_or(false) {
              return (opcodes::WARM_STORAGE_READ_COST, 0);
          }

          // First write to slot
          if current == original {
              if is_zero(original) {
                  (opcodes::SSTORE_SET_GAS, 0)
              } else if new.iter().all(|&x| x == 0) {
                  (opcodes::SSTORE_RESET_GAS, opcodes::SSTORE_CLEARS_SCHEDULE as i64)
              } else {
                  (opcodes::SSTORE_RESET_GAS, 0)
              }
          } else {
              let mut refund = 0;
              if !is_zero(original) {
                  if is_zero(current) && !new.iter().all(|&x| x == 0) {
                      refund -= opcodes::SSTORE_CLEARS_SCHEDULE as i64;
                  }
                  if !is_zero(current) && new.iter().all(|&x| x == 0) {
                      refund += opcodes::SSTORE_CLEARS_SCHEDULE as i64;
                  }
              }
              (opcodes::WARM_STORAGE_READ_COST, refund)
          }
      }

      // Calculate final refund (capped at 1/5 of used gas per EIP-3529)
      pub fn get_final_refund(&self, gas_used: u64) -> u64 {
          std::cmp::min(self.refund.max(0) as u64, gas_used / 5)
      }


    }
    pub fn vec_u8_to_hex(bytes: Vec<u8>) -> String {
        let strs: Vec<String> = bytes.iter().map(|b| format!("{:02X}", b)).collect();
        strs.join("")
    }

    pub fn valid_dest(code: &[u8], pos: usize) -> bool {
        if code[pos] == 0x5b {
            return true;
        }
        false
    }

    pub fn upper_multiple_of_32(n: usize) -> usize {
        ((n - 1) | 31) + 1
    }
