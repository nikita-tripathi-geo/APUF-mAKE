from sys import byteorder

def xor_bytes(a: bytes, b: bytes) -> bytes:
    '''
    Performs a byte-wise XOR operation on two byte sequences of equal length.
    
    Args:
        a (bytes): The first byte sequence.
        b (bytes): The second byte sequence, of the same length as `a`.
        
    Returns:
        bytes: Result of XORing each byte in `a` with the corresponding byte in `b`.

    Raises:
        TypeError: If `a` or `b` is not of type `bytes`.
        
    Examples:
        >>> xor_bytes(b'\\x0f\\x0f', b'\\x00\\x0f')
        b'\\x0f\\x00'

        >>> xor_bytes(b'\\x0f\\x0f', b'\\x0f\\x0f')
        b'\\x00\\x00'
        
        >>> xor_bytes(b'\\x01\\x02\\x03', b'\\x01\\x01\\x01')
        b'\\x00\\x03\\x02'

        >>> xor_bytes('string', b'\\x00\\x0f')  # Test non-byte input
        Traceback (most recent call last):
            ...
        TypeError: Both arguments must be of type 'bytes'.

    '''

    # Type check for bytes
    if not isinstance(a, bytes) or not isinstance(b, bytes):
        raise TypeError("Both arguments must be of type 'bytes'.")

    int_a = int.from_bytes(a, byteorder)
    int_b = int.from_bytes(b, byteorder)

    int_xor = int_a ^ int_b

    return int_xor.to_bytes(max(len(a), len(b)), byteorder)


if __name__ == "__main__":
    import doctest
    doctest.testmod()
