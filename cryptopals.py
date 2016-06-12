import time
import string
import random
import binascii
import base64
from operator import itemgetter
import itertools
import collections
try:
    from Crypto.Cipher import AES
except ImportError:
    from Cryptodome.Cipher import AES
import os


def time_it(method):
    def wrapper(*args, **kw):
        startTime = int(round(time.time() * 1000))
        result = method(*args, **kw)
        endTime = int(round(time.time() * 1000))
        print('Function Name: {0} - {1}ms'.format(method.__name__, endTime - startTime))

        return result

    return wrapper

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


def convert_bytes_to_base64(input_string: bytes) -> bytes:
    _hex = binascii.unhexlify(input_string)
    _b64 = binascii.b2a_base64(_hex)
    return _b64


def decrypt_fixed_xor(message, key):
    """
    Decode hex value and xor'd against the key.
    - running a binascii.unhexlify(hex) on the result will reveal the ascii readable content.

    :param message: Expecting a hex value as string or bytes
    :param key: Expecting a hex value as string or bytes
    :return: a hex value in bytes
    """

    if type(message) == str:
        message = bytes.fromhex(message)
    elif type(message) == int:
        message = message.to_bytes(2, 'big')

    if type(key) == str:
        key = binascii.a2b_hex(key)
    elif type(key) == int:
        key = key.to_bytes(2, 'big')

    output = ""
    if len(message) == len(key):
        output = bytes([x ^ y for (x, y) in zip(message, key)])
    elif len(key) == 1:
        padded_list = key * len(message)
        output = bytes([x ^ y for (x, y) in zip(message, padded_list)])

    return binascii.b2a_hex(output)


def score_text(decrypted: bytes) -> float:
    scores = []

    for item in decrypted.decode('utf-8').lower():
        try:
            scores.append(letters[item])

        except KeyError:
            if item in string.printable:
                scores.append(0)
            else:
                scores = [0]
    return sum(scores)


def find_key_and_decrypt_fixed_xor_message(data):
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

        except binascii.Error:
            pass
        except UnicodeDecodeError:
            pass
        except AttributeError:
            pass

    if len(scores) == 0:
        scores.append(('<none>', 0, b'<error>'))
    _key, _, _decrypted = max(scores, key=itemgetter(1))

    return _key, _decrypted


def decrypt_xor(message: bytes, key: bytes) -> bytes:

    keys = itertools.cycle(key)
    output = bytes(x ^ y for x, y in zip(message, keys))

    return output


def encrypt_xor(message: bytes, key: bytes, hexlify=True) -> bytes:

    keys = itertools.cycle(key)
    output = bytes(x ^ y for x, y in zip(message, keys))

    if hexlify:
        output = binascii.hexlify(output)

    return output


def compute_hamming_distance(s1: bytes, s2: bytes) -> int:
    """Return the Hamming distance between equal-length sequences"""
    if len(s1) != len(s2):
        raise ValueError("Undefined for sequences of unequal length")
    if type(s1) != bytes:
        s1 = bytes(s1, 'ascii')
    if type(s2) != bytes:
        s2 = bytes(s2, 'ascii')

    return sum(bin(x ^ y).count("1") for (x, y) in zip(s1, s2))


def get_normalized_hamming_distance(data: bytes, keysize: int) -> float:
    """
    Expects a base64 input

    take the first KEYSIZE worth of bytes,
    and the second KEYSIZE worth of bytes, and find the edit distance between them.
    Normalize this result by dividing by KEYSIZE.
    """

    if type(data) != bytes:
        data = bytes(data, 'ascii')

    # the greater the number of chunks the more likely a good result can be had
    chunks = [data[keysize * n:keysize * (n + 1)] for n in range(0, 20)]
    chunks = [chunk for chunk in chunks if len(chunk) == keysize]
    distances = list(map(compute_hamming_distance, chunks, chunks[1:]))

    return sum(distances) / len(distances) / keysize


def get_secret_key_length_from_encrypted_data(text: bytes) -> int:
    results = dict()
    for keylength in range(2, 40):
        try:
            results[keylength] = get_normalized_hamming_distance(text, keylength)
        except:
            pass
    key_length = sorted(results, key=results.get)[0]

    return key_length


@time_it
def challenge_01() -> None:
    input_string = b"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    # print(binascii.unhexlify(input_string))
    x = convert_bytes_to_base64(input_string)

    assert x.strip() == b"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"


@time_it
def challenge_02() -> None:
    data = "1c0111001f010100061a024b53535009181c"
    key = "686974207468652062756c6c277320657965"

    decrypted = decrypt_fixed_xor(data, key)
    # print(binascii.unhexlify(decrypted))
    assert decrypted == b'746865206b696420646f6e277420706c6179'


@time_it
def challenge_03() -> None:
    """
    Single-byte XOR cipher
    The hex encoded string:

    1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
    ... has been XOR'd against a single character. Find the key, decrypt the message.

    You can do this by hand. But don't: write code to do it for you.

    How?
    """
    data = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    key, decrypted_message = find_key_and_decrypt_fixed_xor_message(data)
    assert decrypted_message == b"Cooking MC's like a pound of bacon"


@time_it
def challenge_04() -> None:
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

            attempt = find_key_and_decrypt_fixed_xor_message(line)
            key, decrypted = attempt
            words = decrypted.decode('utf-8').split()
            english = [word for word in words if word in keywords]
            if english:
                assert decrypted == b'Now that the party is jumping\n'


@time_it
def challenge_05() -> None:
    """
    Implement repeating-key XOR
    Here is the opening stanza of an important work of the English language:

    Burning 'em, if you ain't quick and nimble
    I go crazy when I hear a cymbal
    Encrypt it, under the key "ICE", using repeating-key XOR.

    In repeating-key XOR, you'll sequentially apply each byte of the key;
    the first byte of plaintext will be XOR'd against I, the next C, the next E, then I again for the 4th byte, etc.

    It should come out to:

    0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
    a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
    """

    test = b'0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272' \
           b'a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
    line = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"

    encrypt = encrypt_xor(line, b"ICE")
    assert encrypt == test


def break_repeating_key_xor(message):
    if type(message) == str:
        message = bytes(message)

    key_length = get_secret_key_length_from_encrypted_data(message)

    blocks = [message[index:index + key_length] for index in range(0, len(message), key_length)]

    transposed = dict()
    for block in blocks:
        for index in range(0, key_length):
            if index not in transposed.keys():
                transposed[index] = list()
            if index < len(block):
                transposed[index].append(block[index])

    values = list()
    for index, block in transposed.items():
        values.append(find_key_and_decrypt_fixed_xor_message(block)[0])

    result = [chr(itm) for itm in values]

    return "".join(result)


@time_it
def challenge_06() -> None:
    """
    Break repeating-key XOR
    :return:
    """
    with open("6.txt", 'r') as handle:
        message = handle.read()

        # convert from base64 to bytes
        message = binascii.a2b_base64(message)

    result = break_repeating_key_xor(message)

    assert result == 'Terminator X: Bring the noise'

    # print(decrypt_xor(message, str.encode(result)))


def decrypt_aes(text: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    result = cipher.decrypt(text)

    return result


def encrypt_aes(encrypted: bytes, key: bytes) -> bytes:
    # print(len(key), key, encrypted)
    cipher = AES.new(key, AES.MODE_ECB)
    result = cipher.encrypt(encrypted)
    # print("Decrypted here: {}".format(decrypt_xor(cipher.decrypt(result), b'1')))

    return result


@time_it
def challenge_07() -> None:
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

        lines = result.decode('utf-8').split('\n')
        assert lines[0] == "I'm back and I'm ringin' the bell ", "Decrypt AES Failed."


def detect_ecb_use(text, keysize: int):
    """
    If I understand this correctly - a large enough dataset will likely have something repeated since
    ECB is stateless and deterministic.
    """
    chunks = [text[n:n + keysize] for n in range(0, len(text), keysize)]
    if len(chunks) != len(set(chunks)):
        return True
    return False


@time_it
def challenge_08() -> None:
    """
    8.txt contains a bunch of hex-encoded ciphertexts.
    - One of them has been encrypted with ECB.
    - Detect it.
    - The problem with ECB is that it is stateless and deterministic;
    - the same 16 byte plaintext block will always produce the same 16 byte ciphertext.
    """

    ecb_encrypted_line = 132

    with open("8.txt", 'r') as handle:
        lines = handle.readlines()

    for ln, line in enumerate(lines):
        text = binascii.unhexlify(line.strip('\n'))

        if detect_ecb_use(text, 16):
            break

    assert ecb_encrypted_line == ln


def pkcs_7_padding(text: bytes, pad: int) -> bytes:
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

    padding = pad - len(text) % pad
    hexed = binascii.a2b_hex('{:02}'.format(padding))
    text += (hexed * padding)

    return text

    # results = []
    # blocks = [text[n:n + pad] for n in range(0, len(text), pad)]
    #
    #
    # for block in blocks:
    #     padding = pad - len(block)
    #     if padding == 0:
    #         padding = 16
    #
    #     hexed = binascii.a2b_hex('{:02}'.format(padding))
    #     block += hexed * padding
    #     results.append(block)
    #
    # return results


def pkcs_7_padding_verification(message: bytes) -> bytes:
    """
    Takes a plaintext, determines if it has valid PKCS#7 padding, and strips the padding off.
    :param message:
    :return:
    """
    last_byte = message[-1]
    if message[-last_byte:] != bytes([last_byte] * last_byte):
        raise ValueError('Bad Padding for message: {}'.format(message))
    else:
        result = message[0:-last_byte]

    return result


@time_it
def challenge_09() -> None:
    text = b'YELLOW SUBMARINE'
    assert b'YELLOW SUBMARINE\x04\x04\x04\x04' == pkcs_7_padding(text, 20)


def encrypt_aes_with_custom_cbc(text: bytes, key: bytes, iv: bytes) -> list:
    results = []
    keysize = len(key)
    text = pkcs_7_padding(text, keysize)
    blocks = [text[n:n + keysize] for n in range(0, len(text), keysize)]

    for block in blocks:
        # pad_block = pkcs_7_padding(block, keysize)[0]
        xor_block = encrypt_xor(block, iv, hexlify=False)
        aes_block = encrypt_aes(xor_block, key)
        iv = aes_block
        results.append(aes_block)

    return results


def decrypt_aes_with_custom_cbc(text: bytes, key: bytes, iv: bytes):
    results = []
    keysize = len(key)
    blocks = [text[n:n + keysize] for n in range(0, len(text), keysize)]

    for block in blocks:
        aes_decrypt = decrypt_aes(block, key)
        xor_decrypt = decrypt_xor(aes_decrypt, iv)
        results.append(xor_decrypt)

        iv = block

    return results


@time_it
def challenge_10() -> None:
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
    iv = bytes([0] * 16)
    test_text = b"this is my fancy text statement."
    encrypted = encrypt_aes(test_text, key)
    decrypted = decrypt_aes(encrypted, key)

    assert test_text == decrypted

    text = binascii.a2b_base64(open('10.txt', 'r').read())

    results = decrypt_aes_with_custom_cbc(text, key, iv)
    results = pkcs_7_padding_verification(b''.join(results))
    # print(b''.join(results))
    # print(results_stripped)

    blocks = encrypt_aes_with_custom_cbc(results, key, iv)

    assert text == b"".join(blocks), '{}'.format(blocks)


def generate_random_bytes(length: int) -> bytes:
    return os.urandom(length)


@time_it
def challenge_11() -> object:
    """
    An ECB/CBC detection oracle
    Now that you have ECB and CBC working:

    Write a function to generate a random AES key; that's just 16 random bytes.

    Write a function that encrypts data under an unknown key --- that is, a function that generates a random key and
    encrypts under it.

    The function should look like:

    encryption_oracle(your-input)
    => [MEANINGLESS JIBBER JABBER]
    Under the hood, have the function append 5-10 bytes (count chosen randomly) before the plaintext and 5-10 bytes
    after the plaintext.

    Now, have the function choose to encrypt under ECB 1/2 the time, and under CBC the other half (just use random IVs
    each time for CBC). Use rand(2) to decide which to use.

    Detect the block cipher mode the function is using each time. You should end up with a piece of code that, pointed
    at a block box that might be encrypting ECB or CBC, tells you which one is happening.


    :return:
    """

    def encrypt_oracle(text: bytes):
        random_aes_key = generate_random_bytes(16)
        prefix = generate_random_bytes(random.randint(5, 10))
        postfix = generate_random_bytes(random.randint(5, 10))

        message = b"".join([prefix, text, postfix])

        if random.randint(1, 2) == 2:
            encoding_type = 'ECB'
            # encrypt ECB
            keysize = len(random_aes_key)
            text = pkcs_7_padding(text, keysize)
            blocks = [text[n:n + keysize] for n in range(0, len(text), keysize)]
            encrypted = []
            for block in blocks:
                text = encrypt_aes(block, random_aes_key)
                # print(binascii.hexlify(text))
                encrypted.append(text)
        else:
            # encrypt_CBC
            encoding_type = 'CBC'
            random_iv = generate_random_bytes(16)
            encrypted = encrypt_aes_with_custom_cbc(message, random_aes_key, random_iv)

        return encrypted, encoding_type

    for x in range(10):
        test, is_ecb = encrypt_oracle(b'A'*212)
        testing = b''.join(test)

        testing = binascii.hexlify(testing)
        assert (is_ecb == 'ECB') == detect_ecb_use(testing, len(test[0]))
        # print("Content encrypted as {0}.  Is ECB?: {1}".format(is_ecb, detect_ecb_use(testing, len(test[0]))))

        # print(test)


def encrypt_ecb_oracle(prefix: bytes, text: bytes, random_aes_key: bytes, prepend: bytes = None):

    if prepend:
        message = b''.join([prepend, prefix, text])
    else:
        message = b''.join([prefix, text])

    # encrypt ECB
    keysize = len(random_aes_key)
    message = pkcs_7_padding(message, keysize)
    blocks = [message[n:n + keysize] for n in range(0, len(message), keysize)]
    encrypted = []
    for block in blocks:
        text = encrypt_aes(block, random_aes_key)
        encrypted.append(text)

    return encrypted


def discover_block_size_and_if_ecb(encrypted_message):
    if type(encrypted_message) == list:
        encrypted_message = b''.join(encrypted_message)
    elif type(encrypted_message) == bytes:
        encrypted_message = encrypted_message
    elif type(encrypted_message) == str:
        encrypted_message = bytes(encrypted_message)

    key_length = get_secret_key_length_from_encrypted_data(encrypted_message)
    # print("Number of blocks: {}".format(len(encrypted_blocks)))
    is_ecb = detect_ecb_use(encrypted_message, key_length)

    return key_length, is_ecb


def decrypt_ecb_message_without_key(encrypted_blocks, base64_decoded: bytes, random_aes_key: bytes, prepend=None):
    """
    Built for challenge #12 and #14

    :param encrypted_blocks:
    :param base64_decoded:
    :param random_aes_key:
    :param prepend:
    :return:
    """
    # Create encrypted content
    text_large = b'A' * 512
    encr_large = encrypt_ecb_oracle(text_large, base64_decoded, random_aes_key, prepend=prepend)
    key_length, is_ecb = discover_block_size_and_if_ecb(encr_large)
    # print("Key Length: {0}\nIs ECB: {1}\n".format(key_length, is_ecb))

    prepend_padding_count = obtain_ecb_prepend_padding_count(base64_decoded, random_aes_key, prepend=prepend)

    collector = list()

    for block_idx in range(len(encrypted_blocks)):
        block_text = (b'B' * (prepend_padding_count - key_length)) + b'A' * key_length * block_idx

        current_block = list()
        for length in reversed(range(key_length)):
            text = block_text + b'A' * length  # one block short

            result = encrypt_ecb_oracle(text, base64_decoded[block_idx * 16:], random_aes_key, prepend=prepend)
            if prepend_padding_count > 0:
                result = result[2:]

            decrypted_block = b''.join(current_block)
            _decrypted = False

            for index in range(0, 255):
                if _decrypted is False:

                    text2 = b''.join([text, decrypted_block, chr(index).encode()])

                    if len(text2) <= key_length + len(block_text):

                        result2 = encrypt_ecb_oracle(text2, base64_decoded, random_aes_key, prepend=prepend)
                        if prepend_padding_count > 0:
                            result2 = result2[2:]

                        if block_idx < len(result) and block_idx < len(result2):
                            if result[block_idx] == result2[block_idx]:
                                current_block.append(chr(index).encode())
                                # print(block_idx, len(text2), chr(index), result2[block_idx])
                                _decrypted = True

        collector.append(b"".join(current_block))
    return b''.join(collector)


@time_it
def challenge_12() -> None:
    """
    Byte - at - a - time

    ECB decryption(Simple)
    Copy your oracle function to a new function that encrypts buffers under ECB mode using a
    consistent but unknown key (for instance, assign a single random key, once, to a global variable).

    Now take that same function and have it append to the plaintext, BEFORE ENCRYPTING, the
    following string:

    Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK

    Spoiler alert. Do not decode this string now. Don't do it.

    Base64 decode the string before appending it. Do not base64
    decode the string by hand; make your code do it.The point is that you don't know its contents.

    What you have now is a function that produces:

    AES - 128 - ECB(your - string | | unknown - string, random - key)

    It turns out: you can decrypt "unknown-string" with repeated calls to the oracle function!

    Here's roughly how:

    Feed identical bytes of your-string to the function 1 at a time
    --- start with 1 byte ("A"), then "AA", then "AAA" and so on.

    1. Discover the block size of the cipher. You know it, but do this step anyway
    2. Detect that the function is using ECB. You already know, but do this step anyways.
    3. Knowing the block size, craft an input block that is exactly 1 byte short (for instance, if the block size is
       8 bytes, make "AAAAAAA"). Think about what the oracle function is going to put in that last byte position.
    4. Make a dictionary of every possible last byte by feeding different strings to the oracle; for instance,
       "AAAAAAAA", "AAAAAAAB", "AAAAAAAC", remembering the first block of each invocation.
    5. Match the output of the one-byte-short input to one of the entries in your dictionary. You've now discovered
       the first byte of unknown-string.
    6. Repeat for the next byte.
    """
    base64_encoded = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGll' \
                     'cyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
    base64_decoded = base64.b64decode(base64_encoded)
    random_aes_key = generate_random_bytes(16)

    encrypted_blocks = encrypt_ecb_oracle(b'', base64_decoded, random_aes_key)

    result = decrypt_ecb_message_without_key(encrypted_blocks, base64_decoded, random_aes_key)

    assert result == b"Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby" \
                     b" waving just to say hi\nDid you stop? No, I just drove by\n\x01", 'Decryption Failed!'


def create_structured_cookie(from_email: str) -> collections.OrderedDict:
    """
    A k=v parsing routine for a structured cookie. The routine takes:

    foo=bar&baz=qux&zap=zazzle
    ... and produce:

    {
      foo: 'bar',
      baz: 'qux',
      zap: 'zazzle'
    }

    :param from_email:
    :return:
    """
    kv = collections.OrderedDict()
    items = from_email.split('&')
    for item in items:
        stuff = item.split('=')
        kv[stuff[0]] = stuff[1]

    return kv


@time_it
def challenge_13() -> None:
    """
    ECB cut-and-paste

    :return:
    """

    def profile_for(user_input: str):
        """
        Now write a function that encodes a user profile in that format, given an email address.

        You should have something like:

        profile_for("foo@bar.com")

        ... and it should produce:

        {
          email: 'foo@bar.com',
          uid: 10,
          role: 'user'
        }
        ... encoded as:

        email=foo@bar.com&uid=10&role=user
        Your "profile_for" function should not allow encoding metacharacters (& and =).
        Eat them, quote them, whatever you want to do,
        but don't let people set their email address to "foo@bar.com&role=admin".
        :return:
        """

        # Eat illegals
        illegals = '&='
        for illegal in illegals:
            user_input.replace(illegal, '')

        user_profile = collections.OrderedDict()
        user_profile['email'] = user_input
        user_profile['uid'] = 10
        user_profile['role'] = 'user'

        items = ['{0}={1}'.format(k, v) for k, v in user_profile.items()]
        user_text = '&'.join(items)

        return user_text

    email = 'theadminisfake.test@gmail.' + \
            'admin{}'.format('\x11' * 11) + \
            'com'  # necessary to push 'user' to its own line
    profile = profile_for(email)
    cookie = create_structured_cookie(profile)

    # print(cookie)

    '''
    Now, two more easy functions. Generate a random AES key, then:
        A.	Encrypt the encoded user profile under the key; "provide" that to the "attacker".
        B.	Decrypt the encoded user profile and parse it.

    Using only the user input to profile_for() (as an oracle to generate "valid" ciphertexts)
    and the ciphertexts themselves, make a role=admin profile.
    '''
    random_aes_key = generate_random_bytes(16)
    keysize = len(random_aes_key)
    message = pkcs_7_padding(profile.encode(), keysize)
    for_attacker = encrypt_aes(message, random_aes_key)

    # print("For Attacker: {}".format(for_attacker))

    # to_be_swizzled = pkcs_7_padding(for_attacker, len(random_aes_key))
    to_be_swizzled = [for_attacker[n:n + keysize] for n in range(0, len(for_attacker), keysize)]
    # Reorder the ECB Blocks and throw away the regular user account :)
    final = list()
    final.append(to_be_swizzled[0])
    final.append(to_be_swizzled[1])
    final.append(to_be_swizzled[3])
    final.append(to_be_swizzled[2])

    for_me = decrypt_aes(b''.join(final), random_aes_key)

    assert for_me == b'email=theadminisfake.test@gmail.com&uid=10&' \
                     b'role=admin\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11', 'Admin account could not be hacked!'


def obtain_ecb_pkcs7_count(message, key, prepend=None) -> int:
    text_large = b'A' * 512
    encr_large = encrypt_ecb_oracle(b'', text_large, key, prepend=prepend)
    key_length, is_ecb = discover_block_size_and_if_ecb(encr_large)

    assert is_ecb is True, "ECB not present - unable to discover key length."

    result = 0
    original = encrypt_ecb_oracle(b'', message, key, prepend=prepend)
    original_length = len(original)
    for index in range(key_length):
        prefix = b'X'*index
        new = encrypt_ecb_oracle(prefix, message, key, prepend=prepend)
        if len(new) > original_length:
            result = index-1
            break
    # final_test = encrypt_ecb_oracle(b'A'*18, message, key, random_prepend=prepend)
    # print("Final Test: {}, {}".format(len(final_test), original_length))
    return result


def obtain_ecb_prepend_padding_count(message, key, prepend=None) -> int:

    counter = 0

    # Go through a single block and attempt to crack it.
    # if the last byte is not as expected.  Try one less - repeat
    # hit a block of expectation -- there is a 1/255 shot that it is correct length.
    text_large = b'A' * 256 + message
    encr_large = encrypt_ecb_oracle(b'', text_large, key, prepend=prepend)
    key_length, is_ecb = discover_block_size_and_if_ecb(encr_large)
    # print("KEyLeNgtH: {}".format(key_length))

    assert is_ecb is True, "ECB not present - unable to discover key length."
    for index in range(0, 5):
        prefix = b'A' * (key_length * index)
        result = encrypt_ecb_oracle(prefix, message, key, prepend=prepend)
        blocks_match = result[1] == result[2]

        if blocks_match:
            # print('Block #{} - {}'.format(index, blocks_match))
            reducing_match = True
            while reducing_match is True:
                prefix = prefix[0:(len(prefix) - 1)]
                result = encrypt_ecb_oracle(prefix, message, key, prepend=prepend)
                reducing_match = result[1] == result[2]
                if not reducing_match:
                    # print('\tPrePadding: {}'.format(counter))
                    break
                counter += 1
            counter -= key_length * index
            break
    # print(counter)
    return abs(counter)


@time_it
def challenge_14() -> object:
    """
    Take your oracle function from #12. Now generate a random count of random bytes and prepend this string to every
    plaintext. You are now doing:

    AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)

    :return:
    """

    base64_encoded = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGll' \
                     'cyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
    base64_decoded = base64.b64decode(base64_encoded)
    random_aes_key = generate_random_bytes(16)
    random_prepend = generate_random_bytes(random.randint(1, 15))
    encrypted_blocks = encrypt_ecb_oracle(b'', base64_decoded, random_aes_key, prepend=random_prepend)

    # print("Padding: {}".format(obtain_ecb_pkcs7_count(base64_decoded, random_aes_key, prepend=random_prepend)))
    obtain_ecb_prepend_padding_count(base64_decoded, random_aes_key, prepend=random_prepend)
    # print(decrypt_aes(b''.join(encrypted_blocks), random_aes_key))
    # print("Original Encrypted Blocks: {}".format(len(encrypted_blocks)))

    result = decrypt_ecb_message_without_key(encrypted_blocks, base64_decoded, random_aes_key, prepend=random_prepend)
    assert base64_decoded == result.strip(b'\x01'), 'Decryption failed! {} != {}'.format(base64_decoded, result)


@time_it
def challenge_15() -> None:
    tests = [b"ICE ICE BABY\x04\x04\x04\x04",
             b"ICE ICE BABY\x05\x05\x05\x05",
             b"ICE ICE BABY\x01\x02\x03\x04",
             b"I\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f",
             b"YELLOW SUBMARINE"]

    expected_results = [b'ICE ICE BABY',
                        b'I',
                        b'YELLOW SUBMARINE']

    received_results = list()
    for test in tests:
        try:
            received_results.append(pkcs_7_padding_verification(test))
        except ValueError:
            pass

    for item in received_results:
        assert item in expected_results, 'PKCS7 Padding Verification Failed.'


@time_it
def challenge_16() -> None:
    """
    CBC bitflipping attacks
    Generate a random AES key.

    Combine your padding code and CBC code to write two functions.

    The first function should take an arbitrary input string, prepend the string:

    "comment1=cooking%20MCs;userdata="
    .. and append the string:

    ";comment2=%20like%20a%20pound%20of%20bacon"
    The function should quote out the ";" and "=" characters.

    The function should then pad out the input to the 16-byte AES block length and encrypt it under the random AES key.

    The second function should decrypt the string and look for the characters ";admin=true;" (or, equivalently, decrypt,
    split the string on ";", convert each resulting string into 2-tuples, and look for the "admin" tuple).

    Return true or false based on whether the string exists.

    If you've written the first function properly, it should not be possible to provide user input to it that will
    generate the string the second function is looking for. We'll have to break the crypto to do that.

    Instead, modify the ciphertext (without knowledge of the AES key) to accomplish this.

    You're relying on the fact that in CBC mode, a 1-bit error in a ciphertext block:

    Completely scrambles the block the error occurs in
    Produces the identical 1-bit error(/edit) in the next ciphertext block.
    Stop and think for a second.
    Before you implement this attack, answer this question: why does CBC mode have this property?
    :return:
    """

    def encrypt_using_cbc(message, key):
        prepend = r"comment1=cooking%20MCs;userdata="
        cleaned = message.replace(';', '').replace("=", "")
        append = r";comment2=%20like%20a%20pound%20of%20bacon"

        full_message = '{}{}{}'.format(prepend, cleaned, append).encode()

        encrypted = encrypt_aes_with_custom_cbc(full_message, key, b'YELLOW SUBMARINE')

        return encrypted

    def is_admin(encrypted, random_aes_key):

        decrypted = decrypt_aes_with_custom_cbc(b''.join(encrypted), random_aes_key, b'YELLOW SUBMARINE')
        #print('FUN: {}'.format(decrypted[2]))
        return False if b''.join(decrypted).find(b";admin=true;") == -1 else True

    random_aes_key = generate_random_bytes(16)
    encrypted = encrypt_using_cbc("?admin?true", random_aes_key)

    # for debugging info
    # decrypted = decrypt_aes_with_custom_cbc(b''.join(encrypted), random_aes_key, b'YELLOW SUBMARINE')

    # do something here to make ;admin=true exist in encrypted.
    success = False
    for index in range(0, 255):
        first_array = bytearray(encrypted[1])
        first_array[0] = index
        for index2 in range(0, 255):
            first_array[6] = index2
            encrypted[1] = bytes(first_array)
            result = is_admin(encrypted, random_aes_key)
            if result:
                # print("Hacked Using the following byte Manipulations: {}, {}".format(index, index2))
                success = True
                break
        if success:
            break

    assert success is True, "Unable to hack admin gate!"


@time_it
def challenge_17():
    """
    https://en.wikipedia.org/wiki/Padding_oracle_attack
    http://robertheaton.com/2013/07/29/padding-oracle-attack/

    :return:
    """
    class Server:
        iv = generate_random_bytes(16)
        key = generate_random_bytes(16)
        test_data = [b'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc =',
                     b'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic =',
                     b'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw ==',
                     b'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg ==',
                     b'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
                     b'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA ==',
                     b'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw ==',
                     b'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8 =',
                     b'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g =',
                     b'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93']

        def get_encrypted_blocks(self):
            # The first function should
            # - select at random one of ten strings
            # - generate a random AES key (which it should save for all future encryptions),
            # - pad the string out to the 16-byte AES block size and
            # - CBC-encrypt it under that key,
            # - providing the caller the ciphertext and IV.

            # grab a random string
            random_string = self.test_data[random.randrange(0, len(self.test_data))]
            # random_string = binascii.a2b_base64(random_string)
            # print("-" * 64)
            # print("PRIOR TO ENCRYPTION: {}".format(random_string))
            # print("-" * 64)
            # encrypt using CBC with provided KEY / IV
            encrypted_blocks = encrypt_aes_with_custom_cbc(random_string, self.key, self.iv)

            return encrypted_blocks

        def decrypt_cookie(self, ciphertext):
            # Consume the ciphertext
            # decrypt it,
            # check its padding, and
            # return true or false depending on whether the padding is valid.
            blocks = decrypt_aes_with_custom_cbc(ciphertext, self.key, self.iv)
            message = b''.join(blocks)
            # print("{} (Decrypted)".format(message))

            try:
                pkcs_7_padding_verification(message)

            except ValueError:
                return False

            return True

    server = Server()
    blocks = server.get_encrypted_blocks()

    def side_channel_attack(c1, c2):
        byte_items = []
        results = []
        for slot in range(1, 17):
            # print("Working on byte {}".format(17-slot))
            found = False

            prefix = b'-' * (16-slot)
            postfix = b''

            for counter, b1 in enumerate(byte_items, 1):
                postfix += bytes([b1 ^ slot])

            for index in range(0, 255):
                if found is False:
                    c1a = prefix + bytes([index]) + postfix
                    # print(c1a)
                    assert len(c1a) == 16, "Expected 16 bytes -- got {}".format(len(c1a))

                    ciphertext = b''.join((c1a, c2))
                    # print(ciphertext)
                    if server.decrypt_cookie(ciphertext):
                        """
                        Let b_{-1}  be the last byte of C_{1}.

                        The attacker changes it as follows:
                            b_-1 = b_-1 XOR z1 XOR 0x01, where
                            z_{-1} is the guessed value of the last byte of P_{2}.
                        """

                        # intermediate state
                        i2a = index ^ slot

                        # plaintext reveal
                        p2 = c1[-slot] ^ i2a

                        # These are the bytes that make up the generated encryption block
                        byte_items.insert(0, index ^ slot)

                        # Decrypted Letters
                        results.insert(0, p2)
                        found = True
                        # print("{} - Found ['{}']: hex {}, int {}".format(17 - slot, chr(p2), c1a[-slot], c1a[-slot]))
                else:
                    break

            if len(byte_items) != slot:
                print("[FAILED] Was unable to find byte {} ....".format(17-slot))
                final_results = [chr(result).encode() for result in results]
                print("STRING DECRYPTED: {}".format((b'0' * (17-slot)) + b''.join(final_results)))

                return

        return results

    results = []
    for c1, c2 in zip(blocks, blocks[1:]):
        result = side_channel_attack(c1, c2)
        if result is not None:
            results.append(''.join([chr(item) for item in result]))

    print("-" * 64)
    print("DECRYPTED: {}".format(results))
    print("DECBASE64: {}".format(binascii.a2b_base64(''.join(results))))
    print("-" * 64)


def test():
    # clicking on my Grouse Grind image produced this
    other = b'W1siZiIsIjIwMTUvMDUvMDkvMTMvNDYvNDgvNTIyLzc4ZjRmNTNjZWZlM2YzNjZiMzBhNjJkZTJhODc2NWQ2Il0sWyJwIiwidGh1bWIiLCI4OXgxMjIjIl1d'

    # converting base64 to binary produces the following (which looks like a structure):
    # b'[["f","2015/05/09/13/46/48/522/78f4f53cefe3f366b30a62de2a8765d6"],["p","thumb","89x122#"]]'
    print(binascii.a2b_base64(other))

    # The long hash looks like it might be something interesting?
    message = b"78f4f53cefe3f366b30a62de2a8765d6"
    print(binascii.unhexlify(message))
    # tests say its not AES
    print("ECB?: {}".format(detect_ecb_use(message, 16)))

    # is this XOR'd?
    key = break_repeating_key_xor(message)

    # seems like it may just be nonsense.
    print("Key: {}".format(key))
    print(decrypt_xor(message, str.encode(key)))


if __name__ == "__main__":

    # Set #1
    challenge_01()
    challenge_02()
    challenge_03()
    challenge_04()
    challenge_05()
    challenge_06()
    challenge_07()
    challenge_08()

    # set #2
    challenge_09()
    challenge_10()
    challenge_11()
    challenge_12()
    challenge_13()
    challenge_14()
    challenge_15()
    challenge_16()

    # set #3
    challenge_17()

    # test()
