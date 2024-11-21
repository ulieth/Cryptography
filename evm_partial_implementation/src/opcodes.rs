/// This module implements a basic Ethereum Virtual Machine (EVM) opcode interpreter.
///
/// It defines gas costs for various operations, such as arithmetic, storage, and contract execution.
/// The `Opcode` struct encapsulates information about each opcode, including its name, number of inputs
/// and outputs, and associated gas costs.
///
/// The `new_opcodes` function initializes a mapping of opcodes to their corresponding operations, such
/// as ADD, SUB, CALL, and LOG. The stack operations include standard arithmetic functions, boolean
/// logic, and memory manipulation functions like MLOAD and MSTORE.
///
/// This interpreter handles gas calculation based on EVM specifications, allowing for the simulation
/// of smart contract execution.

/// The general gas cost function, C, for EVM operations is defined in the Yellow Paper as:
/// C(σ, μ, A, I) ≡ Cmem(μ′i) − Cmem(μi) plus additional costs associated with specific operations.
/// These operations, such as SELFDESTRUCT, are assigned different weights based on their computational costs.
/// For example, operations in Wzero (e.g., STOP, RETURN, REVERT) have lower costs, while those in Whigh (e.g., JUMPI) have higher costs.

use super::*;
use std::collections::{HashMap, HashSet};
use crate::types::{Address, H256};
use num_bigint::BigUint;
use num_traits::identities::Zero;
// Constants representing gas prices for various operations in the Ethereum Virtual Machine (EVM).
// These values are derived from the Ethereum Yellow Paper and Ethereum Improvement Proposals (EIPs).
// They serve to quantify the computational cost of executing operations, ensuring fair resource allocation
// and preventing abuse of the network.

// Base costs
pub const GDEFAULT: u64 = 1;
pub const GMEMORY: u64 = 3;
pub const GQUADRATICMEMDENOM: u64 = 512;

// Storage costs per EIP-2929 and EIP-3529
// EIP-3529 removes gas refunds for SELFDESTRUCT, and reduce gas refunds for SSTORE to a lower level
// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2929.md
// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-3529.md
pub const COLD_SLOAD_COST: u64 = 2100;
pub const WARM_STORAGE_READ_COST: u64 = 100;
pub const COLD_ACCOUNT_ACCESS_COST: u64 = 2600;
pub const WARM_ACCOUNT_ACCESS_COST: u64 = 100;
pub const SSTORE_SET_GAS: u64 = 20000;
pub const SSTORE_RESET_GAS: u64 = 2900;
pub const SSTORE_CLEARS_SCHEDULE: u64 = 4800; // EIP-3529 reduced refund

// Memory and copy costs
pub const GCOPY: u64 = 3;
pub const GEXPONENTBYTE: u64 = 10;
pub const EXP_SUPPLEMENTAL_GAS: u64 = 40;

// Contract operations
pub const GCONTRACTBYTE: u64 = 200;
pub const GCALLVALUETRANSFER: u64 = 9000;
pub const GLOGBYTE: u64 = 8;

// Transaction costs per EIP-2028
pub const GTXCOST: u64 = 21000;
pub const GTXDATAZERO: u64 = 4;
pub const GTXDATANONZERO: u64 = 16;

// Access list costs per EIP-2930
pub const ACCESS_LIST_ADDRESS_COST: u64 = 2400;
pub const ACCESS_LIST_STORAGE_KEY_COST: u64 = 1900;

// Contract creation and calls
pub const GCALLNEWACCOUNT: u64 = 25000;
pub const GSTIPEND: u64 = 2300;

// Cryptographic operation costs
pub const GSHA3WORD: u64 = 6;
pub const GECRECOVER: u64 = 3000;

// Track accessed addresses and storage slots for EIP-2929
#[derive(Default)]
pub struct AccessList<H256> {
    addresses: HashSet<Address>,
    storage: HashMap<Address, HashSet<H256>>,
}

impl AccessList {
    pub fn new() -> Self {
        Self::default()
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

// Structure representing an opcode with its attributes,
/// - `name`: The name of the opcode.
/// - `inputs`: The number of items removed from the stack.
/// - `outputs`: The number of items added to the stack.
/// - `gas`: The amount of gas required to execute this opcode.
pub struct Opcode {
    pub name: String,
    pub inputs: u32,
    pub outputs: u32,
    pub gas: u64,
}

// Function to create a new Opcode instance
pub fn new_opcode(name: &str, inputs: u32, outputs: u32, gas: u64) -> Opcode {
    Opcode {
      name: name.to_string(),
      inputs,
      outputs,
      gas,
    }
}

// Function to create a hashmap of opcodes
pub fn new_opcodes() -> HashMap<u8, Opcode> {
    let mut opcodes: HashMap<u8, Opcode> = HashMap::new();
    // 0s: Stop and Arithmetic Operations
    // All arithmetic is modulo 2^256 unless otherwise noted.
    opcodes.insert(0x00, new_opcode("STOP", 0, 0, 0));
    opcodes.insert(0x01, new_opcode("ADD", 2, 1, 3));
    opcodes.insert(0x02, new_opcode("MUL", 2, 1, 5));
    opcodes.insert(0x03, new_opcode("SUB", 2, 1, 3));
    opcodes.insert(0x04, new_opcode("DIV", 2, 1, 5));
    opcodes.insert(0x05, new_opcode("SDIV", 2, 1, 5));
    opcodes.insert(0x06, new_opcode("MOD", 2, 1, 5));
    opcodes.insert(0x07, new_opcode("SMOD", 2, 1, 5));
    opcodes.insert(0x08, new_opcode("ADDMOD", 3, 1, 8));
    opcodes.insert(0x09, new_opcode("MULMOD", 3, 1, 8));
    opcodes.insert(0x0a, new_opcode("EXP", 2, 1, 10));
    opcodes.insert(0x0b, new_opcode("SIGNEXTEND", 2, 1, 5));

    // 10s: Comparison & Bitwise Logic Operations
    opcodes.insert(0x10, new_opcode("LT", 2, 1, 3));
    opcodes.insert(0x11, new_opcode("GT", 2, 1, 3));
    opcodes.insert(0x12, new_opcode("SLT", 2, 1, 3));
    opcodes.insert(0x13, new_opcode("SGT", 2, 1, 3));
    opcodes.insert(0x14, new_opcode("EQ", 2, 1, 3));
    opcodes.insert(0x15, new_opcode("ISZERO", 1, 1, 3));
    opcodes.insert(0x16, new_opcode("AND", 2, 1, 3));
    opcodes.insert(0x17, new_opcode("OR", 2, 1, 3));
    opcodes.insert(0x18, new_opcode("XOR", 2, 1, 3));
    opcodes.insert(0x19, new_opcode("NOT", 1, 1, 3));
    opcodes.insert(0x1a, new_opcode("BYTE", 2, 1, 3));
    opcodes.insert(0x1b, new_opcode("SHL", 2, 1, 3));
    opcodes.insert(0x1c, new_opcode("SHR", 2, 1, 3));
    opcodes.insert(0x1d, new_opcode("SAR", 2, 1, 3));

    // 20s: KECCAK256
    opcodes.insert(0x20, new_opcode("KECCAK256", 2, 1, 30));

    // 30s: Environmental Information
    opcodes.insert(0x30, new_opcode("ADDRESS", 0, 1, 2));
    opcodes.insert(0x31, new_opcode("BALANCE", 1, 1, 100));
    opcodes.insert(0x32, new_opcode("ORIGIN", 0, 1, 2));
    opcodes.insert(0x33, new_opcode("CALLER", 0, 1, 2));
    opcodes.insert(0x34, new_opcode("CALLVALUE", 0, 1, 2));
    opcodes.insert(0x35, new_opcode("CALLDATALOAD", 1, 1, 3));
    opcodes.insert(0x36, new_opcode("CALLDATASIZE", 0, 1, 2));
    opcodes.insert(0x37, new_opcode("CALLDATACOPY", 3, 0, 3));
    opcodes.insert(0x38, new_opcode("CODESIZE", 0, 1, 2));
    opcodes.insert(0x39, new_opcode("CODECOPY", 3, 0, 3));
    opcodes.insert(0x3a, new_opcode("GASPRICE", 0, 1, 2));
    opcodes.insert(0x3b, new_opcode("EXTCODESIZE", 1, 1, 100));
    opcodes.insert(0x3c, new_opcode("EXTCODECOPY", 4, 0, 100));
    opcodes.insert(0x3d, new_opcode("RETURNDATASIZE", 0, 1, 2));
    opcodes.insert(0x3e, new_opcode("RETURNDATACOPY", 3, 0, 3));
    opcodes.insert(0x3f, new_opcode("EXTCODEHASH", 1, 1, 100));

    // 40s: Block Information
    opcodes.insert(0x40, new_opcode("BLOCKHASH", 1, 1, 20));
    opcodes.insert(0x41, new_opcode("COINBASE", 0, 1, 2));
    opcodes.insert(0x42, new_opcode("TIMESTAMP", 0, 1, 2));
    opcodes.insert(0x43, new_opcode("NUMBER", 0, 1, 2));
    opcodes.insert(0x44, new_opcode("PREVRANDAO", 0, 1, 2));
    opcodes.insert(0x45, new_opcode("GASLIMIT", 0, 1, 2));
    opcodes.insert(0x46, new_opcode("CHAINID", 0, 1, 2));
    opcodes.insert(0x47, new_opcode("SELFBALANCE", 0, 1, 5));
    opcodes.insert(0x48, new_opcode("BASEFEE", 0, 1, 2));

    // 50s: Stack, Memory, Storage and Flow Operations
    opcodes.insert(0x50, new_opcode("POP", 1, 0, 2));
    opcodes.insert(0x51, new_opcode("MLOAD", 1, 1, 3));
    opcodes.insert(0x52, new_opcode("MSTORE", 2, 0, 3));
    opcodes.insert(0x53, new_opcode("MSTORE8", 2, 0, 3));
    opcodes.insert(0x54, new_opcode("SLOAD", 1, 1, 100));
    opcodes.insert(0x55, new_opcode("SSTORE", 2, 0, 100));
    opcodes.insert(0x56, new_opcode("JUMP", 1, 0, 8));
    opcodes.insert(0x57, new_opcode("JUMPI", 2, 0, 10));
    opcodes.insert(0x58, new_opcode("PC", 0, 1, 2));
    opcodes.insert(0x59, new_opcode("MSIZE", 0, 1, 2));
    opcodes.insert(0x5a, new_opcode("GAS", 0, 1, 2));
    opcodes.insert(0x5b, new_opcode("JUMPDEST", 0, 0, 1));
    opcodes.insert(0x5e, new_opcode("MCOPY", 3, 0, 3));

    // 5f, 60s & 70s: Push Operations
    opcodes.insert(0x5f, new_opcode("PUSH0", 0, 1, 2));
    for i in 1..33 {
        let name = format!("PUSH{}", i);
        opcodes.insert(0x5f + i, new_opcode(&name, 0, 1, 3));
    }

    // 80s: Duplication Operations
    for i in 1..17 {
      let name = format!("DUP{}", i);
      opcodes.insert(0x7f + i, new_opcode(&name, i as u32, i as u32 + 1, 3));
    // 90s: Exchange Operations
      let name = format!("SWAP{}", i);
      opcodes.insert(0x8f + i, new_opcode(&name, i as u32 + 1, i as u32 + 1, 3));
    }
    // closures
    opcodes.insert(0xf0, new_opcode("CREATE", 3, 1, 32000));
    opcodes.insert(0xf1, new_opcode("CALL", 7, 1, 100));
    opcodes.insert(0xf2, new_opcode("CALLCODE", 7, 1, 100));
    opcodes.insert(0xf3, new_opcode("RETURN", 2, 0, 0));
    opcodes.insert(0xf4, new_opcode("DELEGATECALL", 6, 0, 100));
    opcodes.insert(0xff, new_opcode("SELFDESTRUCT", 1, 0, 5000));


    // a0s: Logging Operations
    opcodes.insert(0xa0, new_opcode("LOG0", 2, 0, 375));
    opcodes.insert(0xa1, new_opcode("LOG1", 3, 0, 750));
    opcodes.insert(0xa2, new_opcode("LOG2", 4, 0, 1125));
    opcodes.insert(0xa3, new_opcode("LOG3", 5, 0, 1500));
    opcodes.insert(0xa4, new_opcode("LOG4", 6, 0, 1875));

    opcodes
}

impl Stack {
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
    pub fn sload(&mut self, access_list: &mut AccessList) -> Result<(), String> {
        let address = self.current_address;
        let slot = H256::from_slice(&self.pop()?);

        let access_cost = if access_list.is_cold_slot(&address, &slot) {
            access_list.mark_slot_warm(address, slot.clone());
            COLD_SLOAD_COST
        } else {
            WARM_STORAGE_READ_COST
        };

        self.gas -= access_cost;

        // Perform the actual SLOAD operation...
        let value = self.storage.get(&slot).cloned().unwrap_or_default();
        self.push(&value)?;

        Ok(())
    }

    // EIP-2929 + EIP-3529: Handle SSTORE with new gas costs and refund rules
    pub fn sstore(&mut self, access_list: &mut AccessList) -> Result<(), String> {
        let address = self.current_address;
        let slot = H256::from_slice(&self.pop()?);
        let new_value = self.pop()?;

        // EIP-2929: Cold/warm slot access
        let access_cost = if access_list.is_cold_slot(&address, &slot) {
            access_list.mark_slot_warm(address, slot.clone());
            COLD_SLOAD_COST
        } else {
            WARM_STORAGE_READ_COST
        };
        self.gas -= access_cost;

        let original_value = self.storage_committed.get(&slot).cloned();
        let current_value = self.storage.get(&slot).cloned();

        // Calculate gas cost and refund based on EIP-3529 rules
        let (cost, refund) = self.calculate_sstore_gas_and_refund(
            &original_value,
            &current_value,
            &new_value
        );

        self.gas -= cost;
        self.refund += refund;

        // Update storage
        if new_value.is_empty() {
            self.storage.remove(&slot);
        } else {
            self.storage.insert(slot, new_value);
        }

        Ok(())
    }

    // Modified BALANCE operation with EIP-2929 access costs
    pub fn balance(&mut self, access_list: &mut AccessList) -> Result<(), String> {
        let address = Address::from_slice(&self.pop()?);
        self.gas -= self.charge_account_access(access_list, &address);
        // Perform actual balance operation...
        Ok(())
    }

    // Calculate SSTORE gas and refund per EIP-3529
    fn calculate_sstore_gas_and_refund(
        &self,
        original: &Option<Vec<u8>>,
        current: &Option<Vec<u8>>,
        new: &Vec<u8>
    ) -> (u64, i64) {
        let is_empty = |value: &Option<Vec<u8>>| value.as_ref().map_or(true, |v| v.is_empty());

        // Current equals new (no-op)
        if current.as_ref() == Some(new) {
            return (WARM_STORAGE_READ_COST, 0);
        }

      // Current equals original (first write)
        if current == original {
            if is_empty(original) {
                // 0 -> nonzero
                (SSTORE_SET_GAS, 0)
            } else if new.is_empty() {
                // nonzero -> 0
                (SSTORE_RESET_GAS, SSTORE_CLEARS_SCHEDULE as i64)
            } else {
                // nonzero -> nonzero
                (SSTORE_RESET_GAS, 0)
            }
        } else {
            // Current does not equal original (dirty slot)
            let mut refund = 0;
            if !is_empty(original) {
                if is_empty(current) && !new.is_empty() {
                    // Recreating an originally existing slot
                    refund -= SSTORE_CLEARS_SCHEDULE as i64;
                }
                if !is_empty(current) && new.is_empty() {
                    // Clearing a slot
                    refund += SSTORE_CLEARS_SCHEDULE as i64;
                }
            }
            (WARM_STORAGE_READ_COST, refund)
        }
    }




  pub fn add(&mut self) -> Result<(), String> {
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
      let b0 = BigUint::from_bytes_be(&self.pop()?[..]);
      let b1 = BigUint::from_bytes_be(&self.pop()?[..]);
      self.push_arbitrary(&(b0 / b1).to_bytes_be());
      Ok(())
  }
  pub fn sdiv(&mut self) -> Result<(), String> {
      Err("unimplemented".to_string())
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
      let mut exp_fee = n_bytes * GEXPONENTBYTE;
      exp_fee += EXP_SUPPLEMENTAL_GAS * n_bytes;
      self.gas -= exp_fee as u64;
      Ok(())
  }

  // boolean
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
      self.gas -= ((GCOPY * length32) / 32) as u64;
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
      if size <= self.mem.len() || start + size <= self.mem.len() {
          return;
      }
      let old_size = self.mem.len() / 32;
      let new_size = upper_multiple_of_32(start + size) / 32;
      let old_total_fee = old_size * GMEMORY + old_size.pow(2) / GQUADRATICMEMDENOM;
      let new_total_fee = new_size * GMEMORY + new_size.pow(2) / GQUADRATICMEMDENOM;
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

  // pub fn `sstore` functon implements EIP-1283
  // EIP-1283 proposes net gas metering changes for SSTORE opcode,
  // enabling new usages for contract storage, and reducing excessive gas costs
  pub fn sstore(&mut self) -> Result<(), String> {
      // https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1283.md
      // Replace SSTORE opcode gas cost calculation (including refunds) with the following logic:
      // 1. If current value equals new value (this is a no-op), 200 gas is deducted.
      // 2. If current value does not equal new value
      //   2.1. If original value equals current value (this storage slot has not been changed by the current execution context)
      //     2.1.1. If original value is 0, 20000 gas is deducted.
      // 	   2.1.2. Otherwise, 5000 gas is deducted. If new value is 0, add 15000 gas to refund counter.
      // 	2.2. If original value does not equal current value (this storage slot is dirty), 200 gas is deducted. Apply both of the following clauses.
      // 	  2.2.1. If original value is not 0
      //       2.2.1.1. If current value is 0 (also means that new value is not 0), remove 15000 gas from refund counter. We can prove that refund counter will never go below 0.
      //       2.2.1.2. If new value is 0 (also means that current value is not 0), add 15000 gas to refund counter.
      // 	  2.2.2. If original value equals new value (this storage slot is reset)
      //       2.2.2.1. If original value is 0, add 19800 gas to refund counter.
      // 	     2.2.2.2. Otherwise, add 4800 gas to refund counter.

      // Handles storage changes with three key values:
      // - Original value: Value at the start of the transaction (if reversion happens)
      // - Current value: Value before this SSTORE operation
      // - New value: Value being written by this SSTORE operation
      let empty: Vec<u8> = Vec::new();
      let key = self.pop()?;
      let value = self.pop()?;
      let original = match self.storage_committed.get(&key) {
          Some(v) => v.clone(),
          None => empty.clone(),
      };

      let current = match self.storage.get(&key) {
          Some(v) => v.clone(),
          None => {
              self.gas -= 2100; // Cold storage access cost
              empty.clone()
          }
      };
      // Case 1: No-op case - current value equals new value
      // This is the cheapest operation as no storage change is needed
      if current == value {
          self.gas -= NETSSTORENOOPGAS; // 200 gas
          return Ok(());
      }
      // Case 2: Fresh slot case - original value equals current value
      // This means this storage slot has not been changed in current execution
      if original == current {
          if original.is_empty() {
              self.gas -= NETSSTOREINITGAS; // 20,000 gas
              return Ok(());
          }
          // Fresh slot being set from non-0 to 0, add refund
          if value.is_empty() {
              self.gas += NETSSTORECLEARREFUND;
          }
          self.gas -= NETSSTORECLEANGAS;
          return Ok(());
      }
      // Case 3: Dirty slot case - original value does not equal current value
      // Handle refunds for original non-zero cases
      if !original.is_empty() {
          if current.is_empty() {
              self.gas -= NETSSTORECLEARREFUND;
          } else if value.is_empty() {
              self.gas += NETSSTORECLEARREFUND;
          }
      }
      // Case 4: Reset case - original value equals new value
      // Provide additional refunds when a dirty slot is reset to its original value
      if original == value {
          if original.is_empty() {
              self.gas += NETSSTORERESETCLEARREFUND;
          } else {
              self.gas += NETSSTORERESETREFUND;
          }
      }
      self.gas -= NETSSTOREDIRTYGAS;
      self.storage.insert(key, value.to_vec());
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
      // TODO
      Ok(())
  }
}

fn valid_dest(code: &[u8], pos: usize) -> bool {
  if code[pos] == 0x5b {
      return true;
  }
  false
}

fn upper_multiple_of_32(n: usize) -> usize {
  ((n - 1) | 31) + 1
}
