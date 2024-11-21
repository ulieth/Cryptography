use evm::*;

/// Helper to create a test stack with a specific address
fn create_test_stack(address: Address) -> Stack {
    let mut stack = Stack::new();
    stack.current_address = address;
    stack
}


#[test]
fn test_cold_warm_address_access() {
    let address = [1u8; 20];
    let mut stack = create_test_stack(address);

    // First access should be cold
    assert!(stack.access_list.is_address_cold(&address));
    stack.charge_address_access(&address).unwrap();

    // Second access should be warm
    assert!(!stack.access_list.is_address_cold(&address));
    assert_eq!(stack.access_list.warm_address_count(), 1);
}
#[test]
fn test_sstore_modify() {
    let address = [3u8; 20];
    let mut stack = create_test_stack(address);
    let key = [1u8; 32];

    // First set a value
    stack.push(key);
    stack.push([1u8; 32]);
    stack.sstore().unwrap();

    // Then modify it
    let initial_gas = stack.gas;
    stack.push(key);
    stack.push([2u8; 32]);
    stack.sstore().unwrap();

    // Should charge warm access + SSTORE_RESET_GAS
    assert_eq!(
        initial_gas - stack.gas,
        opcodes::WARM_STORAGE_READ_COST + opcodes::SSTORE_RESET_GAS
    );
}
#[test]
fn test_sstore_clear_refund() {
    let address = [4u8; 20];
    let mut stack = create_test_stack(address);
    let key = [1u8; 32];

    // First set a non-zero value
    stack.push(key);
    stack.push([1u8; 32]);
    stack.sstore().unwrap();

    // Then clear it
    stack.push(key);
    stack.push([0u8; 32]);
    stack.sstore().unwrap();

    // Should have refund
    assert_eq!(stack.refund, opcodes::SSTORE_CLEARS_SCHEDULE as i64);
}

#[test]
fn test_sstore_first_set() {
    let address = [2u8; 20];
    let mut stack = create_test_stack(address);
    let key = [1u8; 32];
    let value = [1u8; 32];

    // Push key and value
    stack.push(key);
    stack.push(value);

    let initial_gas = stack.gas;
    stack.sstore().unwrap();

    // Should charge cold access + SSTORE_SET_GAS
    assert_eq!(
        initial_gas - stack.gas,
        opcodes::COLD_SLOAD_COST + opcodes::SSTORE_SET_GAS
    );
}
#[test]
fn test_refund_cap() {
    let address = [5u8; 20];
    let mut stack = create_test_stack(address);

    // Set a high refund
    stack.refund = 1000000;
    let gas_used = 1000000;

    // Should be capped at 1/5
    assert_eq!(stack.get_final_refund(gas_used), gas_used / 5);
}

#[test]
fn stack_simple_push_pop() {
    let mut s = Stack::new();
    s.push(u256::str_to_u256("1"));
    s.push(u256::str_to_u256("2"));
    s.push(u256::str_to_u256("3"));
    assert_eq!(s.pop().unwrap(), u256::str_to_u256("3"));
    assert_eq!(s.pop().unwrap(), u256::str_to_u256("2"));
    assert_eq!(s.pop().unwrap(), u256::str_to_u256("1"));
    assert_eq!(s.pop(), Err(format!("pop err"))); // WIP
}

// arithmetic
#[test]
fn execute_opcodes_0() {
    let code = hex::decode("6005600c01").unwrap(); // 5+12
    let calldata = vec![];

    let mut s = Stack::new();
    s.execute(&code, &calldata, false).unwrap();
    assert_eq!(s.pop().unwrap(), u256::str_to_u256("17"));
    assert_eq!(s.gas, 9999999991);
    assert_eq!(s.pc, 5);
}

#[test]
fn execute_opcodes_1() {
    let code = hex::decode("60056004016000526001601ff3").unwrap();
    let calldata = vec![];

    let mut s = Stack::new();
    let out = s.execute(&code, &calldata, false).unwrap();

    assert_eq!(out[0], 0x09);
    assert_eq!(s.gas, 9999999976);
    assert_eq!(s.pc, 12);
    // assert_eq!(s.pop(), err); // TODO expect error as stack is empty
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
    // contains calldata
    let code = hex::decode("60003560203501").unwrap();
    let calldata = hex::decode("00000000000000000000000000000000000000000000000000000000000000050000000000000000000000000000000000000000000000000000000000000004").unwrap();

    let mut s = Stack::new();
    s.execute(&code, &calldata, false).unwrap();

    assert_eq!(s.gas, 9999999985);
    assert_eq!(s.pc, 7);
    assert_eq!(s.pop().unwrap(), u256::str_to_u256("9"));
}

// storage and execution
#[test]
fn execute_opcodes_4() {
    // contains loops
    let code = hex::decode("6000356000525b600160005103600052600051600657").unwrap();
    let calldata =
        hex::decode("0000000000000000000000000000000000000000000000000000000000000005").unwrap();

    let mut s = Stack::new();
    s.execute(&code, &calldata, false).unwrap();

    assert_eq!(s.gas, 9999999795);
    assert_eq!(s.pc, 22);
    assert_eq!(s.stack.len(), 0);
}
#[test]
fn execute_opcodes_5() {
    // contains loops, without using mem
    let code = hex::decode("6000355b6001900380600357").unwrap();
    let calldata =
        hex::decode("0000000000000000000000000000000000000000000000000000000000000001").unwrap();

    let mut s = Stack::new();
    s.execute(&code, &calldata, false).unwrap();

    assert_eq!(s.gas, 9999999968);
    assert_eq!(s.pc, 12);

    let code = hex::decode("6000355b6001900380600357").unwrap();
    let calldata =
        hex::decode("0000000000000000000000000000000000000000000000000000000000000002").unwrap();

    let mut s = Stack::new();
    s.execute(&code, &calldata, false).unwrap();

    assert_eq!(s.gas, 9999999942);
    assert_eq!(s.pc, 12);

    let code = hex::decode("6000355b6001900380600357").unwrap();
    let calldata =
        hex::decode("0000000000000000000000000000000000000000000000000000000000000005").unwrap();

    let mut s = Stack::new();
    s.execute(&code, &calldata, false).unwrap();

    assert_eq!(s.gas, 9999999864);
    assert_eq!(s.pc, 12);
}
#[test]
fn execute_opcodes_6() {
    // 0x36: calldata_size
    let code = hex::decode("366020036101000a600035045b6001900380600c57").unwrap();
    let calldata = hex::decode("01").unwrap();

    let mut s = Stack::new();
    s.execute(&code, &calldata, false).unwrap();

    assert_eq!(s.gas, 9999999892);
    assert_eq!(s.pc, 21);
    assert_eq!(s.stack.len(), 1);

    let code = hex::decode("366020036101000a600035045b6001900380600c57").unwrap();
    let calldata = hex::decode("05").unwrap();

    let mut s = Stack::new();
    s.execute(&code, &calldata, false).unwrap();

    assert_eq!(s.gas, 9999999788);
    assert_eq!(s.pc, 21);
    assert_eq!(s.stack.len(), 1);

    let code = hex::decode("366020036101000a600035045b6001900380600c57").unwrap();
    let calldata = hex::decode("0101").unwrap();

    let mut s = Stack::new();
    s.execute(&code, &calldata, false).unwrap();

    assert_eq!(s.gas, 9999993236);
    assert_eq!(s.pc, 21);
    assert_eq!(s.stack.len(), 1);
}

#[test]
fn execute_opcodes_7() {
    // contract deployment (code_copy)
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
fn execute_exceptions() {
    let mut s = Stack::new();
    let calldata = hex::decode("").unwrap();

    let code = hex::decode("5f").unwrap();
    let out = s.execute(&code, &calldata, false);
    assert_eq!(out, Err(format!("invalid opcode 5f")));

    let code = hex::decode("56").unwrap();
    let out = s.execute(&code, &calldata, false);
    assert_eq!(out, Err(format!("pop err")));

    let code = hex::decode("600056").unwrap();
    let out = s.execute(&code, &calldata, false);
    assert_eq!(out, Err(format!("not valid dest: 00")));

    s.gas = 1;
    let code = hex::decode("6000").unwrap();
    let out = s.execute(&code, &calldata, false);
    assert_eq!(out, Err(format!("out of gas")));
}

#[test]
fn execute_opcodes_8() {
    let code = hex::decode("611000805151").unwrap();
    let calldata = hex::decode("").unwrap();

    let mut s = Stack::new();
    s.execute(&code, &calldata, false).unwrap();

    assert_eq!(s.gas, 9999999569);
    assert_eq!(s.pc, 6);
    assert_eq!(s.stack.len(), 2);
    assert_eq!(s.mem.len(), 4128);
}

#[test]
fn execute_opcodes_9() {
    // sstore (0x55)
    let code = hex::decode("60026000556001600055").unwrap();
    let calldata = hex::decode("").unwrap();

    let mut s = Stack::new();
    s.execute(&code, &calldata, false).unwrap();

    // assert_eq!(s.gas, 9999977788); // TODO WIP geth reported gas
    assert_eq!(s.gas, 9999955788);
    assert_eq!(s.pc, 10);
    assert_eq!(s.stack.len(), 0);
    assert_eq!(s.storage.len(), 0);
}

#[test]
fn execute_opcodes_9() {
    // sstore (0x55) with EIP-2929 cold/warm access
    let code = hex::decode( "606060405260e060020a6000350463a5f3c23b8114601a575b005b60243560043501600055601856").unwrap();
    let calldata = hex::decode("a5f3c23b00000000000000000000000000000000000000000000000000000000000000050000000000000000000000000000000000000000000000000000000000000004").unwrap();

    let mut s = Stack::new();
    let initial_gas = s.gas;
    s.execute(&code, &calldata, false).unwrap();

    // First SSTORE: cold access (2100) + SSTORE_SET_GAS (20000)
    // Second SSTORE: warm access (100) + SSTORE_RESET_GAS (2900)
    let expected_gas = initial_gas - (
        opcodes::COLD_SLOAD_COST +  // 2100 (cold access)
        opcodes::SSTORE_SET_GAS +   // 20000 (initial set)
        opcodes::WARM_STORAGE_READ_COST + // 100 (warm access)
        opcodes::SSTORE_RESET_GAS   // 2900 (modification)
    );

    assert_eq!(s.gas, expected_gas);
    assert_eq!(s.pc, 10);
    assert_eq!(s.stack.len(), 0);
    assert_eq!(s.storage.len(), 1); // Value should remain in storage
}

// Storage tests with refunds
#[test]
fn test_sstore_with_refunds() {
    let code = hex::decode("6001600055600060005560016000556000600055").unwrap();
    let calldata = vec![];

    let mut s = Stack::new();
    let initial_gas = s.gas;
    s.execute(&code, &calldata, false).unwrap();

    // Sequence of operations:
    // 1. Set 0->1 (cold): COLD_SLOAD_COST + SSTORE_SET_GAS
    // 2. Set 1->0 (warm): WARM_STORAGE_READ_COST + SSTORE_RESET_GAS + refund
    // 3. Set 0->1 (warm): WARM_STORAGE_READ_COST + SSTORE_SET_GAS - previous refund
    // 4. Set 1->0 (warm): WARM_STORAGE_READ_COST + SSTORE_RESET_GAS + refund

    let expected_gas = initial_gas - (
        opcodes::COLD_SLOAD_COST + opcodes::SSTORE_SET_GAS +
        opcodes::WARM_STORAGE_READ_COST * 3 +
        opcodes::SSTORE_RESET_GAS * 2 +
        opcodes::SSTORE_SET_GAS
    );

    assert_eq!(s.gas, expected_gas);
    // Final refund should be SSTORE_CLEARS_SCHEDULE
    assert_eq!(s.refund, opcodes::SSTORE_CLEARS_SCHEDULE as i64);
}

#[test]
fn test_storage_patterns() {
    // Test various storage patterns with warm/cold access
    let code = hex::decode("60016000556000600055600160005560006000556001600055").unwrap();
    let calldata = vec![];

    let mut s = Stack::new();
    s.execute(&code, &calldata, false).unwrap();

    // Check refund is capped correctly
    let gas_used = 10000000000 - s.gas;
    assert!(s.get_final_refund(gas_used) <= gas_used / 5);
}

#[test]
fn test_access_list_behavior() {
    let address = [1u8; 20];
    let mut s = create_test_stack(address);

    // First storage operation should be cold
    let code = hex::decode("6001600055").unwrap();
    let initial_gas = s.gas;
    s.execute(&code, &vec![], false).unwrap();

    assert_eq!(
        initial_gas - s.gas,
        opcodes::COLD_SLOAD_COST + opcodes::SSTORE_SET_GAS
    );

    // Second operation to same slot should be warm
    let code = hex::decode("6002600055").unwrap();
    let initial_gas = s.gas;
    s.execute(&code, &vec![], false).unwrap();

    assert_eq!(
        initial_gas - s.gas,
        opcodes::WARM_STORAGE_READ_COST + opcodes::SSTORE_RESET_GAS
    );
}
