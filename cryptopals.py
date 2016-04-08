import string
import binascii
from operator import itemgetter
import itertools
from Crypto.Cipher import AES


letters = {' ': 0.13000000,
           'e': 0.12575645,
           't': 0.09085226,
           'a': 0.08000395,
           'o': 0.07591270,
           'i': 0.06920007,
           'n': 0.06903785,
           's': 0.06340880,
           'r': 0.06236609,
           'h': 0.05959034,
           'd': 0.04317924,
           'l': 0.04057231,
           'u': 0.02841783,
           'c': 0.02575785,
           'm': 0.02560994,
           'f': 0.02350463,
           'w': 0.02224893,
           'g': 0.01982677,
           'y': 0.01900888,
           'p': 0.01795742,
           'b': 0.01535701,
           'v': 0.00981717,
           'k': 0.00739906,
           'x': 0.00179556,
           'j': 0.00145188,
           'q': 0.00117571,
           'z': 0.00079130}


def convert_bytes_to_base64(input_string):
    _hex = binascii.unhexlify(input_string)
    _b64 = binascii.b2a_base64(_hex)
    return _b64


def decrypt_fixed_xor(input, key):
    """
    Decode hex value and xor'd against the key.
    - running a binascii.unhexlify(hex) on the result will reveal the ascii readable content.

    :param input: Expecting a hex value as string or bytes
    :param key: Expecting a hex value as string or bytes
    :return: a hex value in bytes
    """

    if type(input) == str:
        input = bytes.fromhex(input)
    elif type(input) == int:
        input = input.to_bytes(2, 'big')

    if type(key) == str:
        key = binascii.a2b_hex(key)
    elif type(key) == int:
        key = key.to_bytes(2, 'big')

    output = ""
    if len(input) == len(key):
        output = bytes([x ^ y for (x, y) in zip(input, key)])
    elif len(key) == 1:
        padded_list = key * len(input)
        output = bytes([x ^ y for (x, y) in zip(input, padded_list)])

    return binascii.b2a_hex(output)


def score_text(decrypted):
    scores = []

    for item in decrypted.decode('utf-8').lower():
        try:
            scores.append(letters[item])

        except KeyError as e:
            if item in string.printable:
                scores.append(0)
            else:
                scores = [0]
    return sum(scores)


def find_key_and_decrypt_message(data):
    """
    Devise some method for "scoring" a piece of English plaintext. Character frequency is a good metric.
    Evaluate each output and choose the one with the best score.
    """

    scores = list()
    for key in range(0, 255):
        hexed = str(hex(key))[2:]

        try:
            decrypted_xor = decrypt_fixed_xor(data, hexed)
            decrypted = binascii.unhexlify(decrypted_xor)
            scores.append((key, score_text(decrypted), decrypted))

        except binascii.Error as e:
            pass
        except UnicodeDecodeError as e:
            pass
        except AttributeError as e:
            pass

    if len(scores) == 0:
        scores.append(('<none>', 0, b'<error>'))
    _key, _, _decrypted = max(scores, key=itemgetter(1))

    return _key, _decrypted


def decrypt_xor(input: bytes, key: bytes):
    #input = binascii.unhexlify(input)
    keys = itertools.cycle(key)

    a3 = bytes(x ^ y for (x, y) in zip(input, keys))

    return a3


def encrypt_xor(input: bytes, key: bytes):
    # ensure we are working with bytes
    if type(input) == str:
        input = bytes(input, 'ascii')

    keys = itertools.cycle(key)

    output = bytes([x ^ y for (x, y) in zip(input, keys)])

    return binascii.hexlify(output)


def compute_hamming_distance(s1: bytes, s2: bytes):
    """Return the Hamming distance between equal-length sequences"""
    if len(s1) != len(s2):
        raise ValueError("Undefined for sequences of unequal length")
    if type(s1) != bytes:
        s1 = bytes(s1, 'ascii')
    if type(s2) != bytes:
        s2 = bytes(s2, 'ascii')

    return sum(bin(x ^ y).count("1") for (x, y) in zip(s1, s2))


def get_normalized_hamming_distance(input: bytes, keysize: int):
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
    chunks = [chunk for chunk in chunks if len(chunk) == keysize]
    distances = list(map(compute_hamming_distance, chunks, chunks[1:]))

    return sum(distances) / len(distances) / keysize


def get_secret_key_length_from_encrypted_data(text: bytes):
    results = dict()
    for keylength in range(2, 40):
        try:
            results[keylength] = get_normalized_hamming_distance(text, keylength)
        except:
            pass
    key_length = sorted(results, key=results.get)[0]

    return key_length

def challenge_01():
    input_string = b"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    # print(binascii.unhexlify(input_string))
    x = convert_bytes_to_base64(input_string)

    assert x.strip() == b"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"



def challenge_02():
    data = "1c0111001f010100061a024b53535009181c"
    key = "686974207468652062756c6c277320657965"

    decrypted = decrypt_fixed_xor(data, key)
    # print(binascii.unhexlify(decrypted))
    assert decrypted == b'746865206b696420646f6e277420706c6179'


def challenge_03():
    """
    Single-byte XOR cipher
    The hex encoded string:

    1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
    ... has been XOR'd against a single character. Find the key, decrypt the message.

    You can do this by hand. But don't: write code to do it for you.

    How?
    """
    data = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    key, decrypted_message = find_key_and_decrypt_message(data)
    assert decrypted_message == b"Cooking MC's like a pound of bacon"


def challenge_04():
    """
    Detect single-character XOR
    One of the 60-character strings in this file has been encrypted by single-character XOR.

    Find it.

    (Your code from #3 should help.)
    """

    # obtained by http://www.dummies.com/how-to/content/top-50-most-commonly-used-words-in-english.html
    keywords = ["the", "he", "at", "but", "there", "of",
                "was", "be", "not", "use", "and", "for",
                "this", "what", "an", "a", "on", "have",
                "all", "each", "to", "are", "from",
                "were", "which", "in", "as", "or", "we",
                "she", "is", "with", "when", "do",
                "you", "his", "had", "your", "how",
                "that", "they", "by", "can", "their",
                "it", "I", "word", "said", "if"]

    with open("4.txt", 'r') as handle:
        for line in handle.readlines():
            line = binascii.a2b_hex(line.strip())

            attempt = find_key_and_decrypt_message(line)
            key, decrypted = attempt
            words = decrypted.decode('utf-8').split()
            english = [word for word in words if word in keywords]
            if english:
                assert decrypted == b'Now that the party is jumping\n'


def challenge_05():
    """
    Implement repeating-key XOR
    Here is the opening stanza of an important work of the English language:

    Burning 'em, if you ain't quick and nimble
    I go crazy when I hear a cymbal
    Encrypt it, under the key "ICE", using repeating-key XOR.

    In repeating-key XOR, you'll sequentially apply each byte of the key;
    the first byte of plaintext will be XOR'd against I, the next C, the next E, then I again for the 4th byte, and so on.

    It should come out to:

    0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
    a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
    Encrypt a bunch of stuff using your repeating-key XOR function. Encrypt your mail.
    Encrypt your password file. Your .sig file. Get a feel for it. I promise, we aren't wasting your time with this.
    """

    test = b'0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
    line = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"

    encrypt = encrypt_xor(line, b"ICE")
    assert encrypt == test


def challenge_06():
    with open("6.txt", 'r') as handle:
        text = binascii.a2b_base64(handle.read())

        key_length = get_secret_key_length_from_encrypted_data(text)

        blocks = [text[index:index + key_length] for index in range(0, len(text), key_length)]

        transposed = dict()
        for block in blocks:
            for index in range(0, key_length):
                if index not in transposed.keys():
                    transposed[index] = list()
                if index < len(block):
                    transposed[index].append(block[index])

        values = list()
        for index, block in transposed.items():
            values.append(find_key_and_decrypt_message(block)[0])

        result = [chr(itm) for itm in values]
        result = "".join(result)
        assert result == 'Terminator X: Bring the noise'
        """
        print("KEY: {}".format(result))

        # result = "Terminator X: Bring the noise"
        _key = str.encode(result)

        lines = []
        for block in blocks:
            stuff = encrypt_xor(block, key=_key)
            lines.append(binascii.unhexlify(stuff).decode('utf-8'))

        print("".join(lines))
        """


def decrypt_aes(text, key):
    cipher = AES.new(key, AES.MODE_ECB)
    result = cipher.decrypt(text)

    return result


def encrypt_aes(encrypted, key):
    cipher = AES.new(key, AES.MODE_ECB)
    result = cipher.encrypt(encrypted)

    return result


def challenge_07():
    """
    AES in ECB mode
    The Base64-encoded content in this file has been encrypted via AES-128 in ECB mode under the key

    "YELLOW SUBMARINE".
    (case-sensitive, without the quotes; exactly 16 characters; I like "YELLOW SUBMARINE" because it's exactly 16 bytes
    long, and now you do too).

    Decrypt it. You know the key, after all.

    Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.
    """

    key = b'YELLOW SUBMARINE'

    with open("7.txt", 'r') as handle:
        text = binascii.a2b_base64(handle.read())

        result = decrypt_aes(text, key)

        for line in result.decode('utf-8').split('\n'):
            print(line)


def challenge_08():
    """
    8.txt contains a bunch of hex-encoded ciphertexts.
    - One of them has been encrypted with ECB.
    - Detect it.
    - The problem with ECB is that it is stateless and deterministic;
    - the same 16 byte plaintext block will always produce the same 16 byte ciphertext.
    """
    def detect_ecb_use(text, keysize):
        """
        If I understand this correctly - a large enough dataset will likely have something repeated, revealing a clue
        that the text could be encoded with ECB.
        """
        chunks = [text[n:n+keysize] for n in range(0, len(text), keysize)]
        if len(chunks) != len(set(chunks)):
            return True
        return False

    with open("8.txt", 'r') as handle:
        lines = handle.readlines()
        for ln, line in enumerate(lines):
            text = binascii.unhexlify(line.strip('\n'))
            if detect_ecb_use(text, 16):
                print(ln, line)


def pkcs_7_padding(text: bytes, pad: int):
    """
    A block cipher transforms a fixed - sized block(usually 8 or 16 bytes) of plaintext into
    ciphertext. But we almost never want to transform a single block; we encrypt irregularly - sized messages.

    One way we account for irregularly - sized messages is by padding, creating a plaintext that is an even multiple of
    the blocksize. The most popular padding scheme is called PKCS  # 7.

    So: pad any block to a specific block length, by appending the number of bytes of padding to the end of the block.

    For instance,

    "YELLOW SUBMARINE"
    ...
    padded to 20 bytes would be:

    "YELLOW SUBMARINE\x04\x04\x04\x04"
    """
    results = []
    blocks = [text[n:n + pad] for n in range(0, len(text), pad)]
    for block in blocks:
        padding = pad - len(block)
        if padding != 0:
            hexed = binascii.a2b_hex('{:02}'.format(padding))
            block += hexed*padding
        results.append(block)

    return results


def challenge_09():
    text = b'YELLOW SUBMARINE'
    print(pkcs_7_padding(text, 20))

def challenge_10():
    """
    CBC mode is a block cipher mode that allows us to encrypt irregularly-sized messages, despite the fact that a block
    cipher natively only transforms individual blocks.  In CBC mode, each ciphertext block is added to the next
    plaintext block before the next call to the cipher core.

    The first plaintext block, which has no associated previous ciphertext block, is added to a
    "fake 0th ciphertext block" called the initialization vector, or IV.

    Implement CBC mode by hand by taking the ECB function you wrote earlier, making it encrypt instead of decrypt
    (verify this by decrypting whatever you encrypt to test), and using your XOR function from the previous exercise
    to combine them.

    The file is intelligible (somewhat) when CBC decrypted against "YELLOW SUBMARINE" with an IV of all ASCII 0
    (\x00\x00\x00 &c)
    """

    key = b'YELLOW SUBMARINE'
    iv = b"\x00"*16
    test_text = b"this is my fancy text statement."
    encrypted = encrypt_aes(test_text, key)
    decrypted = decrypt_aes(encrypted, key)

    print(encrypted)
    print(decrypted)

    def encrypt_aes_with_custom_cbc(text, key, iv):
        results = []
        keysize = len(key)
        blocks = [text[n:n + keysize] for n in range(0, len(text), keysize)]
        for block in blocks:
            padded_blocks = pkcs_7_padding(block, len(key))
            for padded_block in padded_blocks:
                xor_encrypt = encrypt_xor(padded_block, iv)
                encrypt = encrypt_aes(xor_encrypt, key)
                iv = encrypt
                results.append(encrypt)

        for itm in results:
            print(itm)
        return results

    def decrypt_aes_with_custom_cbc(text, key, iv):
        results = []
        keysize = len(key) * 2
        blocks = [text[n:n + keysize] for n in range(0, len(text), keysize)]
        print("------")
        for block in blocks:
            print(block)
            xor_decrypt = decrypt_xor(block, iv)
            iv = block
            results.append(xor_decrypt)

        return results


    encrypted = encrypt_aes_with_custom_cbc("Hello World 1234" *10, key, iv)
    encrypted = b"".join(encrypted)
    decrypted = decrypt_aes_with_custom_cbc(encrypted, key, iv)
    print(decrypted)
#    with open('10.txt', 'rb') as handle:
#        text = handle.read()
#        decrypt_aes_with_custom_cbc(text, key, "\x00"*16)


if __name__ == "__main__":

    challenge_01()
    challenge_02()
    challenge_03()
    challenge_04()
    challenge_05()
    challenge_06()
    challenge_07()
    challenge_08()
    challenge_09()
    challenge_10()
