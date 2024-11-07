from sys import byteorder

def xor_bytes(a: bytes, b: bytes) -> bytes:
    '''
    '''
    # TODO add error checking like different lengths, etc.
    # TODO add unit tests

    int_a = int.from_bytes(a, byteorder)
    int_b = int.from_bytes(b, byteorder)

    int_xor = int_a ^ int_b

    return int_xor.to_bytes(len(a), byteorder)
