def detect_unchecked_calls(transactions):
    unchecked_calls = []
    for tx in transactions:
        # Assuming each transaction has 'method' and 'return_value' attributes
        if tx.method in ['transfer', 'send'] and tx.return_value is None:
            unchecked_calls.append(tx)
    return unchecked_calls

# Example usage:
if __name__ == '__main__':
    sample_transactions = [
        {'method': 'transfer', 'return_value': None},
        {'method': 'send', 'return_value': 'success'},
        {'method': 'transfer', 'return_value': None},
    ]
    print(detect_unchecked_calls(sample_transactions))