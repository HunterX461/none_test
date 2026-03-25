def scan_file(file_path):
    # Import all new detectors
    from detectors import reentrancy, integer_arithmetic, unchecked_calls, delegatecall_injection, tx_origin

    # Integrate the detectors into the scan process
    results = []
    results.append(reentrancy.check(file_path))
    results.append(integer_arithmetic.check(file_path))
    results.append(unchecked_calls.check(file_path))
    results.append(delegatecall_injection.check(file_path))
    results.append(tx_origin.check(file_path))

    return results