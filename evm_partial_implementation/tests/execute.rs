use evm_partial_implementation::{Stack, u256, opcodes};

// Helper function for test_access_list_behavior test
fn create_test_stack(address: [u8; 20]) -> Stack {
    let mut s = Stack::new();
    s.current_address = address;
    s
}
// arithmetic operations
#[test]
// add operation
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
    assert_eq!(s.pop(), Err("pop err".to_string())); // TODO expect error as stack is empty

}

#[test]
fn execute_opcodes_2() {

    let code = hex::decode("61010161010201").unwrap();
    let calldata = vec![];

    let mut s = Stack::new();
    s.execute(&code, &calldata, false).unwrap();

    // assert_eq!(out[0], 0x09);
    assert_eq!(s.gas, 9999999991);
    assert_eq!(s.pc, 7);
    assert_eq!(s.pop().unwrap(), u256::str_to_u256("515"));
}
#[test]
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
