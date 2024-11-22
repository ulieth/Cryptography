// This module implements a basic Ethereum Virtual Machine (EVM) opcode interpreter.
//
// It defines gas costs for various operations, such as arithmetic, storage, and contract execution.
// The `Opcode` struct encapsulates information about each opcode, including its name, number of inputs
// and outputs, and associated gas costs.
//
// The `new_opcodes` function initializes a mapping of opcodes to their corresponding operations, such
// as ADD, SUB, CALL, and LOG. The stack operations include standard arithmetic functions, boolean
// logic, and memory manipulation functions like MLOAD and MSTORE.
//
// This interpreter handles gas calculation based on EVM specifications, allowing for the simulation
// of smart contract execution.

// The general gas cost function, C, for EVM operations is defined in the Yellow Paper as:
// C(σ, μ, A, I) ≡ Cmem(μ′i) − Cmem(μi) plus additional costs associated with specific operations.
// For example, operations in Wzero (e.g., STOP, RETURN, REVERT) have lower costs, while those in Whigh (e.g., JUMPI) have higher costs.

// Constants representing gas prices for various operations in the Ethereum Virtual Machine (EVM).
// These values are derived from the Ethereum Yellow Paper and Ethereum Improvement Proposals (EIPs).
// They serve to quantify the computational cost of executing operations, ensuring fair resource allocation
// and preventing abuse of the network.
use std::collections::HashMap;
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
pub const GEXPONENTBYTE: u64 = 50; // ???
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
//https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2929.md
// Increase the gas cost of SLOAD (0x54) to 2100,
// and the *CALL opcode family (0xf1, f2, f4, fA),
// BALANCE (0x31) and the EXT* opcode family (0x3b, 0x3c, 0x3f) to 2600.
// Exempts (i) precompiles, and (ii) addresses and storage slots
// that have already been accessed in the same transaction (100 gas).

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
    opcodes.insert(0x31, new_opcode("BALANCE", 1, 1, COLD_ACCOUNT_ACCESS_COST));
    opcodes.insert(0x32, new_opcode("ORIGIN", 0, 1, 2));
    opcodes.insert(0x33, new_opcode("CALLER", 0, 1, 2));
    opcodes.insert(0x34, new_opcode("CALLVALUE", 0, 1, 2));
    opcodes.insert(0x35, new_opcode("CALLDATALOAD", 1, 1, 3));
    opcodes.insert(0x36, new_opcode("CALLDATASIZE", 0, 1, 2));
    opcodes.insert(0x37, new_opcode("CALLDATACOPY", 3, 0, 3));
    opcodes.insert(0x38, new_opcode("CODESIZE", 0, 1, 2));
    opcodes.insert(0x39, new_opcode("CODECOPY", 3, 0, 3));
    opcodes.insert(0x3a, new_opcode("GASPRICE", 0, 1, 2));
    opcodes.insert(0x3b, new_opcode("EXTCODESIZE", 1, 1, COLD_ACCOUNT_ACCESS_COST ));
    opcodes.insert(0x3c, new_opcode("EXTCODECOPY", 4, 0, COLD_ACCOUNT_ACCESS_COST));
    opcodes.insert(0x3d, new_opcode("RETURNDATASIZE", 0, 1, 2));
    opcodes.insert(0x3e, new_opcode("RETURNDATACOPY", 3, 0, 3));
    opcodes.insert(0x3f, new_opcode("EXTCODEHASH", 1, 1, COLD_ACCOUNT_ACCESS_COST));

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
    opcodes.insert(0x54, new_opcode("SLOAD", 1, 1, COLD_SLOAD_COST));
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
    opcodes.insert(0xf1, new_opcode("CALL", 7, 1, COLD_ACCOUNT_ACCESS_COST));
    opcodes.insert(0xf2, new_opcode("CALLCODE", 7, 1, COLD_ACCOUNT_ACCESS_COST));
    opcodes.insert(0xf3, new_opcode("RETURN", 2, 0, 0));
    opcodes.insert(0xf4, new_opcode("DELEGATECALL", 6, 0, COLD_ACCOUNT_ACCESS_COST));
    opcodes.insert(0xff, new_opcode("SELFDESTRUCT", 1, 0, 5000));

    // a0s: Logging Operations
    opcodes.insert(0xa0, new_opcode("LOG0", 2, 0, 375));
    opcodes.insert(0xa1, new_opcode("LOG1", 3, 0, 750));
    opcodes.insert(0xa2, new_opcode("LOG2", 4, 0, 1125));
    opcodes.insert(0xa3, new_opcode("LOG3", 5, 0, 1500));
    opcodes.insert(0xa4, new_opcode("LOG4", 6, 0, 1875));

    opcodes
}
