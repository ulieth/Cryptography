use evm_partial_implementation::{Stack, u256};
use evm_partial_implementation::opcodes::{
  COLD_SLOAD_COST,
  WARM_STORAGE_READ_COST,
};

// Arithmetic operations
#[test]
// Add operation
fn execute_opcodes_0() {
    let mut s = Stack::new();
    // Code: PUSH1 5 (0x60, 0x05), PUSH1 12 (0x60, 0x0c), ADD (0x01)
    let code = hex::decode("6005600c01").unwrap(); // outputs the byte array: [96, 5, 96, 12, 1]
    let calldata = vec![];

    s.execute(&code, &calldata, false).unwrap();

    assert_eq!(s.pop().unwrap(), u256::str_to_u256("17")); // 5 + 12 = 17
    assert_eq!(s.gas, 9999999991);  // Check remaining gas
    assert_eq!(s.pc, 5);  // Check program counter position
}
#[test]
// MSTORE and RETURN operations
fn execute_opcodes_1() {
    let mut s = Stack::new();
    // Code: PUSH1 5 (0x60, 0x05), PUSH1 4 (0x60, 0x04), ADD (0x01), PUSH1 0 (0x60, 0x00)
    // MSTORE (0x50), PUSH1 1 (0x60, 0x01), PUSH1 31 (0x60, 0x1f), RETURN (0xf3) returns memory slice
    let code = hex::decode("60056004016000526001601ff3").unwrap();
    let calldata = vec![];
    let out = s.execute(&code, &calldata, false).unwrap();

    assert_eq!(out[0], 0x09);
    assert_eq!(s.gas, 9999999976);
    assert_eq!(s.pc, 12);
    assert_eq!(s.pop(), Err("The stack is empty".to_string()));

}
#[test]
// PUSH2 and ADD operations
fn execute_opcodes_2() {
    let mut s = Stack::new();
    // Code: PUSH2 257 (0x61 0x0101), PUSH2 258 (0x61 0x0102), ADD (0x01)
    let code = hex::decode("61010161010201").unwrap();
    let calldata = vec![];  // No calldata needed for this test
    s.execute(&code, &calldata, false).unwrap();
    assert_eq!(s.gas, 9999999991);  // Check remaining gas
    assert_eq!(s.pc, 7);  // Program counter should be at the end (2 PUSH2s = 3 bytes each + 1 ADD)
    assert_eq!(s.pop().unwrap(), u256::str_to_u256("515")); // 257 + 258 = 515
}
#[test]
// CALLDATALOAD
fn execute_opcodes_3() {
    let mut s = Stack::new();
    // Code: PUSH1 0 (0x60, 0x00), CALLDATALOAD (0x35), PUSH1 32 (0x60, 0x20),
    // CALLDATALOAD (0x35), ADD (0x01)
    let code = hex::decode("60003560203501").unwrap();

    // Calldata contains two 32-byte values: 5 and 4
    let calldata = hex::decode("00000000000000000000000000000000000000000000000000000000000000050000000000000000000000000000000000000000000000000000000000000004").unwrap();

    s.execute(&code, &calldata, false).unwrap();

    assert_eq!(s.gas, 9999999985);
    assert_eq!(s.pc, 7);
    assert_eq!(s.pop().unwrap(), u256::str_to_u256("9")); // 5 + 4 = 9
}
#[test]
// The code implements a countdown loop from 5 to 0
// using JUMPI to loop back to JUMPDEST while value is not zero.
fn execute_opcodes_4() {
    let mut s = Stack::new();
    // Code: PUSH1 0 (0x60, 0x00) - Push 0 for CALLDATALOAD position
    // CALLDATALOAD (0x35) - Load value from calldata - gets 5
    // PUSH1 0 (0x60, 0x00) - Push memory position 0
    // MSTORE (0x52) - Store value in memory at position 0
    // JUMPDEST (0x5b) - Mark valid jump destination for loop
    // PUSH1 1 (0x60, 0x01) - Push value 1 for subtraction
    // PUSH1 0 (0x60, 0x00) - Push memory position 0
    // MLOAD (0x51) - Load current value from memory
    // SUB (0x03) - Subtract 1 from current value
    // PUSH1 0 (0x60, 0x00) - Push memory position 0
    // MSTORE (0x52) - Store decremented value back to memory
    // PUSH1 0 (0x60, 0x00) - Push memory position 0
    // MLOAD (0x51) - Load value for comparison
    // PUSH1 6 (0x60, 0x06) - Push jump destination (position of JUMPDEST)
    // JUMPI (0x57) - Jump back to JUMPDEST if value is not zero
    let code = hex::decode("6000356000525b600160005103600052600051600657").unwrap();

    // Calldata: 32-byte value of 5 padded with zeros
    let calldata = hex::decode("0000000000000000000000000000000000000000000000000000000000000005").unwrap();

    s.execute(&code, &calldata, false).unwrap();
    assert_eq!(s.gas, 9999999795);  // Check gas after loop
    assert_eq!(s.pc, 22);           // Check final program counter
    assert_eq!(s.stack.len(), 0);   // Stack should be empty after loop
}
#[test]
// Countdown loop without memory
fn execute_opcodes_5() {
    // contains loops, without using mem
    // Code: PUSH1 0 (0x60, 0x00) - Push 0 for CALLDATALOAD position
    // CALLDATALOAD (0x35) - Load value from calldata
    // JUMPDEST (0x5b) - Mark valid jump destination for loop //
    // PUSH1 1 (0x60, 0x01) - Push value 1
    // SWAP1 (0x90) - Swap counter with 1
    // SUB (0x03) - Subtract 1 from counter
    // DUP1 (0x80) - Duplicate counter for comparison
    // PUSH1 3 (0x60, 0x03) - Push jump destination
    // JUMPI (0x57) - Jump back if counter not zero
    let code = hex::decode("6000355b6001900380600357").unwrap();
    // Single interation
    let calldata =
        hex::decode("0000000000000000000000000000000000000000000000000000000000000001").unwrap();

    let mut s = Stack::new();
    s.execute(&code, &calldata, false).unwrap();

    assert_eq!(s.gas, 9999999968);
    assert_eq!(s.pc, 12);

    let code = hex::decode("6000355b6001900380600357").unwrap();
    // Two iterations
    let calldata =
        hex::decode("0000000000000000000000000000000000000000000000000000000000000002").unwrap();

    let mut s = Stack::new();
    s.execute(&code, &calldata, false).unwrap();

    assert_eq!(s.gas, 9999999942);
    assert_eq!(s.pc, 12);

    let code = hex::decode("6000355b6001900380600357").unwrap();
    // Five iterations
    let calldata =
        hex::decode("0000000000000000000000000000000000000000000000000000000000000005").unwrap();

    let mut s = Stack::new();
    s.execute(&code, &calldata, false).unwrap();

    assert_eq!(s.gas, 9999999864);
    assert_eq!(s.pc, 12);
}

#[test]
// This test simulates a contract deployment sequence
fn execute_opcodes_6() {
    // PUSH1 0x05 (0x60, 0x05) - Push 5 onto stack (length of runtime code)
    // DUP1 (0x80) - Duplicate the value 5
    // PUSH1 0x0b (0x60, 0x0b) - Push 11 onto stack (offset for runtime code)
    // PUSH1 0x00 (0x60, 0x00) - Push 0 onto stack (destination in memory)
    // CODECOPY (0x39) - Copy runtime code to memory
    // PUSH1 0x00 (0x60, 0x00) - Push 0 onto stack (offset in memory)
    // RETURN (0xf3) - Return runtime code from memory
    // Runtime code:
    // PUSH1 0x05 (0x60, 0x05) - Push 5
    // PUSH1 0x04 (0x60, 0x04) - Push 4
    // ADD (0x01) - Add 5 + 4
    let code = hex::decode("600580600b6000396000f36005600401").unwrap();
    let calldata = hex::decode("").unwrap();

    let mut s = Stack::new();
    let out = s.execute(&code, &calldata, true).unwrap();

    assert_eq!(s.gas, 9999999976);
    assert_eq!(s.pc, 10);
    assert_eq!(s.stack.len(), 0);
    assert_eq!(s.mem.len(), 32);
    assert_eq!(
        s.mem,
        hex::decode("6005600401000000000000000000000000000000000000000000000000000000").unwrap()
    );
    assert_eq!(out, hex::decode("6005600401").unwrap());
}
#[test]
// SLOAD cold, SLOAD warm (same slot), SLOAD cold (different slot)
fn execute_opcodes_7() {
    let mut s = Stack::new();
    // PUSH1 0x01 (0x60 0x01) - slot 1
    // SLOAD (0x54) - cold access
    // PUSH1 0x01 (0x60 0x01) - slot 1 again
    // SLOAD (0x54) - warm access
    // PUSH1 0x02 (0x60 0x02) - slot 2
    // SLOAD (0x54) - cold access
    let code = hex::decode("600154600154600254").unwrap();
    let calldata = vec![];
    let initial_gas = s.gas;
    s.execute(&code, &calldata, false).unwrap();

    // Calculate gas usage
    let total_gas_used = initial_gas - s.gas;

    // Expected gas costs:
    // 1. First SLOAD: COLD_SLOAD_COST + PUSH1 base cost (3)
    // 2. Second SLOAD: WARM_STORAGE_READ_COST + PUSH1 base cost (3)
    // 3. Third SLOAD: COLD_SLOAD_COST + PUSH1 base cost (3)
    let expected_min_gas = COLD_SLOAD_COST + WARM_STORAGE_READ_COST + COLD_SLOAD_COST + 9; // 9 for three PUSH1 operations

    // Verify total gas usage
    assert!(total_gas_used >= expected_min_gas);

    // Verify program counter reached the end
    assert_eq!(s.pc, code.len());
}
#[test]
// memory extension
fn execute_opcodes_8() {
    let mut s = Stack::new();
    // PUSH2 0x1000 (0x61 0x1000)  4096
    // DUP1 (0x80) - Duplicate top value
    // MLOAD (0x51) - Load from memory at offset 0x1000
    // MLOAD (0x51) - Load from memory at same offset
    let code = hex::decode("611000805151").unwrap();
    let calldata = vec![];

    s.execute(&code, &calldata, false).unwrap();

    // Gas checks:
    // - PUSH2: 3 gas
    // - DUP1: 3 gas
    // - First MLOAD: extends memory to 4096 + 32 = 4128 bytes
    //   Memory expansion cost = (⌊4128 / 32⌋) * 3 + (⌊4128 / 32⌋)^2 / 512
    // - Second MLOAD: uses same memory size, only base cost
    // Initial gas: 10000000000
    // Expected remaining: 9999999569
    assert_eq!(s.gas, 9999999569);

    // Program counter should be at the end of code
    assert_eq!(s.pc, 6);

    // Stack should contain:
    // - Value loaded by second MLOAD
    // - Value loaded by first MLOAD
    assert_eq!(s.stack.len(), 2);

    // Memory should be extended to handle MLOAD at offset 0x1000 (4096)
    // Plus 32 bytes for the word size = 4128
    assert_eq!(s.mem.len(), 4128);
}
// Testing exceptions
#[test]
fn execute_exceptions() {
    let mut s = Stack::new();
    let calldata = hex::decode("").unwrap();
    let code = hex::decode("5f").unwrap();
    let out = s.execute(&code, &calldata, false);
    assert_eq!(out, Err(format!("unimplemented 5f")));

    let code = hex::decode("56").unwrap();
    let out = s.execute(&code, &calldata, false);
    assert_eq!(out, Err(format!("The stack is empty")));

    let code = hex::decode("600056").unwrap();
    let out = s.execute(&code, &calldata, false);
    assert_eq!(out, Err(format!("not valid dest: 00")));

    s.gas = 1;
    let code = hex::decode("6000").unwrap();
    let out = s.execute(&code, &calldata, false);
    assert_eq!(out, Err(format!("Out of gas")));
}
