import string
import binascii
import cryptopals


def compute_hamming_distance(s1, s2):
    """Return the Hamming distance between equal-length sequences"""
    if len(s1) != len(s2):
        raise ValueError("Undefined for sequences of unequal length")
    if type(s1) != bytes:
        s1 = bytes(s1, 'ascii')
    if type(s2) != bytes:
        s2 = bytes(s2, 'ascii')

    return sum(bin(x ^ y).count("1") for (x, y) in zip(s1, s2))


def get_normalized_hamming_distance(input, keysize):
    """
    Expects a base64 input

    take the first KEYSIZE worth of bytes,
    and the second KEYSIZE worth of bytes, and find the edit distance between them.
    Normalize this result by dividing by KEYSIZE.
    """

    if type(input) != bytes:
        input = bytes(input, 'ascii')

    # the greater the number of chunks the more likely a good result can be had
    chunks = [input[keysize*n:keysize*(n+1)] for n in range(0, 20)]

    distances = list(map(compute_hamming_distance, chunks, chunks[1:]))

    return sum(distances) / len(distances) / keysize

def test_001():
    s1 = 'this is a test'
    s2 = 'wokka wokka!!!'
    hamming_test = compute_hamming_distance(s1, s2)
    #print(hamming_test)
    assert hamming_test == 37


def test_002():
    """
    This fails -- running hex on the hamming distance does not satisfy the tests we're trying to do.
    :return:
    """
    with open("6.txt", 'r') as handle:
        text = binascii.a2b_base64(handle.read())
        text_hex = binascii.hexlify(text)

        results = dict()
        for keylength in range(2, 40):
            results[keylength] = get_normalized_hamming_distance(text_hex, keylength)

        print(sorted(results, key=results.get)[0:4])

if __name__ == "__main__":

    with open("6.txt", 'r') as handle:
        text = binascii.a2b_base64(handle.read())

        results = dict()
        for keylength in range(2, 40):
            results[keylength] = get_normalized_hamming_distance(text, keylength)

        key_length = sorted(results, key=results.get)[0]

        blocks = [text[index:index+key_length] for index in range(0, len(text), key_length)]

        transposed = dict()
        for block in blocks:
            for index in range(0, key_length):
                if index not in transposed.keys():
                    transposed[index] = list()
                if index < len(block):
                    transposed[index].append(block[index])

        values = list()
        for index, block in transposed.items():
            values.append(cryptopals.find_key_and_decrypt_message(block)[0])

        result = [chr(itm) for itm in values]
        result = "".join(result)

        print(result)

        #result = "Terminator X: Bring the noise"
        _key = str.encode(result)
        #print(_key)
        for block in blocks:
            stuff = cryptopals.encrypt_xor(block, key=_key)
            print(binascii.unhexlify(stuff))