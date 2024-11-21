#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
pub mod opcodes;
pub mod u256;
mod types;
use types::{Address, H256};

// Access list tracking for EIP-2929
#[derive(Default)]
pub struct AccessList {
    addresses: HashSet<Address>,
    storage: HashMap<Address, HashSet<H256>>,
}

impl AccessList {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_address_cold(&self, address: &Address) -> bool {
        !self.addresses.contains(address)
    }

    pub fn is_storage_cold(&self, address: &Address, key: &H256) -> bool {
        !self.storage
            .get(address)
            .map_or(false, |slots| slots.contains(key))
    }

    pub fn mark_address_warm(&mut self, address: Address) {
        self.addresses.insert(address);
    }

    pub fn mark_storage_warm(&mut self, address: Address, key: H256) {
        self.storage.entry(address).or_default().insert(key);
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
        };
        s.opcodes = opcodes::new_opcodes();
        s
    }
    pub fn print_stack(&self) {
        println!("stack ({}):", self.stack.len());
        for i in (0..self.stack.len()).rev() {
            // println!("{:x}", &self.stack[i][28..]);
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
    pub fn push(&mut self, b: [u8; 32]) {
        self.stack.push(b);
    }
    // push_arbitrary performs a push, but first converting the arbitrary-length
    // input into a 32 byte array
    pub fn push_arbitrary(&mut self, b: &[u8]) {
        // TODO if b.len()>32 return error
        let mut d: [u8; 32] = [0; 32];
        d[32 - b.len()..].copy_from_slice(b);
        self.stack.push(d);
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
        match self.stack.pop() {
            Some(x) => Ok(x),
            None => Err("pop err".to_string()), // WIP
        }
    }
    pub fn peek(&mut self) -> Result<[u8; 32], String> {
        if self.stack.is_empty() {
            return Err("peek err".to_string());
        }
        Ok(self.stack[self.stack.len() - 1])
    }
    pub fn substract_gas(&mut self, val: u64) -> Result<(), String> {
        if self.gas < val {
            return Err("out of gas".to_string());
        }
        self.gas -= val;
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
        let l = code.len();

        while self.pc < l {
            let opcode = code[self.pc];
            if !self.opcodes.contains_key(&opcode) {
                return Err(format!("invalid opcode {:x}", opcode));
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

            match opcode & 0xf0 {
                0x00 => {
                    // arithmetic
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
                        // 0x0b => self.sign_extend(),
                        _ => return Err(format!("unimplemented {:x}", opcode)),
                    }
                    self.pc += 1;
                }
                0x10 => {
                    // arithmetic
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
                        0x35 => self.calldata_load(&calldata)?,
                        0x36 => self.calldata_size(&calldata),
                        0x39 => self.code_copy(&code)?,
                        _ => return Err(format!("unimplemented {:x}", opcode)),
                    }
                    self.pc += 1;
                }
                0x50 => {
                    self.pc += 1;
                    match opcode {
                        0x51 => self.mload()?,
                        0x52 => self.mstore()?,
                        0x55 => self.sstore()?,
                        0x56 => self.jump(code)?,
                        0x57 => self.jump_i(code)?,
                        0x5b => self.jump_dest()?,
                        _ => return Err(format!("unimplemented {:x}", opcode)),
                    }
                }
                0x60 | 0x70 => {
                    // push
                    let n = (opcode - 0x5f) as usize;
                    self.push_arbitrary(&code[self.pc + 1..self.pc + 1 + n]);
                    self.pc += 1 + n;
                }
                0x80 => {
                    // 0x8x dup
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
                    if opcode == 0xf3 {
                        let pos_to_return = u256::u256_to_u64(self.pop()?) as usize;
                        let len_to_return = u256::u256_to_u64(self.pop()?) as usize;
                        return Ok(self.mem[pos_to_return..pos_to_return + len_to_return].to_vec());
                    }
                }
                _ => {
                    return Err(format!("unimplemented {:x}", opcode));
                }
            }
            // Subtract base gas cost
            self.substract_gas(base_gas)?;
        }
        Ok(Vec::new())
    }

    pub fn sstore(&mut self) -> Result<(), String> {
      let key = self.pop()?;
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
