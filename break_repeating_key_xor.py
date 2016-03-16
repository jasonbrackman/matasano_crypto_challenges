def compute_hamming_distance(s1, s2):
    """Return the Hamming distance between equal-length sequences"""
    if len(s1) != len(s2):
        raise ValueError("Undefined for sequences of unequal length")
    if type(s1) != bytes:
        s1 = bytes(s1, 'ascii')
    if type(s2) != bytes:
        s2 = bytes(s2, 'ascii')

    return sum(bin(x ^ y).count("1") for (x, y) in zip(s1, s2))

if __name__ == "__main__":
    s1 = 'this is a test'
    s2 = 'wokka wokka!!!'
    print(compute_hamming_distance(s1, s2))
