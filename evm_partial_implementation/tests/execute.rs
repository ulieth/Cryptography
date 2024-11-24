use evm_partial_implementation::{Stack, u256, opcodes};

// Helper function for test_access_list_behavior test
fn create_test_stack(address: [u8; 20]) -> Stack {
    let mut s = Stack::new();
    s.current_address = address;
    s
}
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
