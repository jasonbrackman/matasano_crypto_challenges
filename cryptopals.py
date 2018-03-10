import string
import struct
import binascii
from operator import itemgetter
import itertools
import collections
import language
try:
    from Crypto.Cipher import AES
    from Crypto.Util import Counter
except ImportError:
    from Cryptodome.Cipher import AES
    from Cryptodome.Util import Counter
import os

english = language.Language()


def find_key_and_decrypt_fixed_xor(message: bytes):
    """
    Devise some method for "scoring" a piece of English plaintext. Character frequency is a good metric.
    Evaluate each output and choose the one with the best score.
    """

    scores = list()
    for key in range(0, 256):
        try:
            decrypted = decrypt_xor(message, bytes([key]))
            score = english.score_text(decrypted)
            if score > 0:
                scores.append((key, english.score_text(decrypted), decrypted))

        except UnicodeDecodeError as e:
            scores.append((0, 0, b'<error>'))

    # Best Raw Guess
    _key, _, _decrypted = max(scores, key=itemgetter(1))

    return bytes([_key]), _decrypted


def decrypt_xor(message: bytes, key: bytes, hexlify=False) -> bytes:
    """
    Decode hex value and xor'd against the key - if key is short -- it is cycled (repeating xor)

    :param message: Expecting a hex value as bytes
    :param key: Expecting a hex value as bytes
    :return: decoded text in bytes
    """
    if hexlify:
        message = binascii.unhexlify(message)

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

    return sum(bin(x ^ y).count("1") for (x, y) in zip(s1, s2))


def get_normalized_hamming_distance(data: bytes, keysize: int) -> float:
    """
    take the first KEYSIZE worth of bytes,
    and the second KEYSIZE worth of bytes, and find the edit distance between them.
    Normalize this result by dividing by KEYSIZE.
    """

    # the greater the number of chunks the more likely a good result can be had
    chunks = [data[keysize * n:keysize * (n + 1)] for n in range(1, 20)]
    chunks = [chunk for chunk in chunks if len(chunk) == keysize]
    if len(chunks) == 1:
        return 100.0
    distances = list(map(compute_hamming_distance, chunks, chunks[1:]))

    return sum(distances) / len(distances) / keysize


def get_secret_key_length_from_encrypted_data(text: bytes) -> int:
    """A range of tests will take place to the length of 40 or the length of the text passed in."""

    max_length = 40 if len(text) > 40 else len(text)
    results = {length: get_normalized_hamming_distance(text, length) for length in range(1, max_length)}

    # Return the sorted dict's values first item - which will be the lowest score (Hamming Distance)
    results_ = sorted(results, key=results.get)
    key_length = results_[0]

    return key_length


def break_repeating_key_xor(message: bytes, key_length=None):

    if key_length is None:
        key_length = get_secret_key_length_from_encrypted_data(message)

    blocks = [message[index:index + key_length] for index in range(0, len(message), key_length)]
    transposed = transpose(blocks)

    values = [find_key_and_decrypt_fixed_xor(block)[0] for block in transposed]
    result = [itm for itm in values]

    return b"".join(result)


def decrypt_aes(text: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    result = cipher.decrypt(text)

    return result


def encrypt_aes(text: bytes, key: bytes) -> bytes:
    # print(len(key), key, encrypted)
    cipher = AES.new(key, AES.MODE_ECB)
    result = cipher.encrypt(text)
    # print("Decrypted here: {}".format(decrypt_xor(cipher.decrypt(result), b'1')))

    return result


def detect_ecb_use(text: bytes, keysize: int):
    """
    If I understand this correctly - a large enough dataset will likely have something repeated since
    ECB is stateless and deterministic.
    """
    chunks = [text[n:n + keysize] for n in range(0, len(text), keysize)]
    if len(chunks) != len(set(chunks)):
        return True
    return False


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


def generate_random_bytes(length: int) -> bytes:
    return os.urandom(length)


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


def generate_keystream(nonce, counter):
    """

    :param nonce: 64 bit unsigned little endian
    :param counter: 64 bit little endian block count (byte count / keylength)
    :return: 128bit / 16byte string
    """
    format = '<q'  # < = little endian
                   # q = convert hex
    c_nonce = struct.pack(format, nonce)
    c_counter = struct.pack(format, counter)

    return b''.join((c_nonce, c_counter))


def aes_with_custom_ctr(message, key, nonce):
    results = []
    keysize = len(key)
    blocks = [message[n:n + keysize] for n in range(0, len(message), keysize)]

    for counter, block in enumerate(blocks):

        keystream = generate_keystream(nonce, counter)
        aes_block = encrypt_aes(keystream, key)
        xor_block = encrypt_xor(aes_block, block, hexlify=False)

        results.append(xor_block[0:len(block)])

    return b''.join(results)


def transpose(blocks: list) -> list:
    """
    Takes in a list of same sized byte strings and transposes them so that all the first items are together, all the
    second items are together and so on.
    Example:

        original:   abcd, hijk, opqr, ...
        transposed: aho, bip, cjq, dkr, ...

    :param blocks: list() -- expecting a list of bytes but could contain anything.
    :return: list()
    """

    transposed = list()
    for index in range(0, len(blocks[0])):
        transposed.append([block[index] for block in blocks if len(block) > index])

    return transposed


class MT19337:
    # w: word size (in number of bits)
    # n: degree of recurrence
    # m: middle word, an offset used in the recurrence relation defining the series x, 1 ≤ m < n
    # r: separation point of one word, or the number of bits of the lower bitmask, 0 ≤ r ≤ w - 1
    w, n, m, r = 32, 624, 397, 31

    # self.lower_mask = hex((1<<31)-1)
    lower_mask = 0x7fffffff
    upper_mask = 0xffffffff & -lower_mask
    # print('LM: {}'.format(hex(lower_mask)))
    # print('UM: {}'.format(hex(upper_mask)))

    # The value for f for MT19937 is 1812433253
    f = 0x6c078965

    a = 0x9908B0DF
    u, d = 11, 0xFFFFFFFF
    s, b = 7, 0x9D2C5680
    t, c = 15, 0xEFC60000
    l = 18

    def __init__(self, seed):

        # w: word size (in number of bits)
        # n: degree of recurrence
        # m: middle word, an offset used in the recurrence relation defining the series x, 1 ≤ m < n
        # r: separation point of one word, or the number of bits of the lower bitmask, 0 ≤ r ≤ w - 1
        # w, n, m, r = 32, 624, 397, 31

        # // Create a length n array to store the state of the generator
        # int[0..n-1] MT
        # int index := n+1
        # const int lower_mask = (1 << r) - 1 // That is, the binary number of r 1's
        # const int upper_mask = lowest w bits of (not lower_mask)

        self.mt = [0] * self.n  # list of ints
        self.index = self.n
        self.seed = seed
        self.seed_mt(self.seed)

    # // Initialize the generator from a seed
    #  function seed_mt(int seed) {
    #      index := n
    #      MT[0] := seed
    #      for i from 1 to (n - 1) { // loop over each element
    #          MT[i] := lowest w bits of (f * (MT[i-1] xor (MT[i-1] >> (w-2))) + i)
    #      }
    #  }
    def seed_mt(self, seed):
        self.mt[0] = seed
        for index in range(1, 624):
            self.mt[index] = 0xffffffff & (self.f * (self.mt[index - 1] ^ (self.mt[index - 1] >> 30)) + index)

    # // Extract a tempered value based on MT[index]
    # // calling twist() every n numbers
    # function extract_number() {
    #   if index >= n {
    #       if index > n {
    #           error "Generator was never seeded"
    #       // Alternatively, seed with constant value; 5489 is used in reference C code[45]
    #       }
    #       twist()
    #   }
    #
    #   int y := MT[index]
    #   y := y xor ((y >> u) and d)
    #   y := y xor ((y << s) and b)
    #   y := y xor ((y << t) and c)
    #   y := y xor (y >> l)
    #
    #   index := index + 1
    #   return lowest w bits of (y)
    # }

    def extract_number(self):
        if self.index >= self.n:
            self.twist()

        y = self.mt[self.index]
        print('ya1:', y)
        y ^= (y >> self.u) & self.d
        y ^= (y << self.s) & self.b
        y ^= (y << self.t) & self.c
        y ^= y >> self.l

        self.index += 1

        return y

    @staticmethod
    def untemper(y):

        y ^= y >> MT19337.l
        y ^= ((y << MT19337.t) & MT19337.c)
        y = MT19337.untemperC(y)
        y = MT19337.untemperD(y)
        print('yb1:', y)

        return y

    @staticmethod
    def untemperC(y):
        """
        Based on code from:
        https://github.com/gaganpreet/matasano-crypto-3/blob/ab1f8684d3730eb67029e0d6c9e53113a2dedcee/src/clone_mt.py
        """

        mask = MT19337.b

        a = y ^ ((y << 7) & mask)
        b = y ^ ((a << 7) & mask)
        c = y ^ ((b << 7) & mask)
        d = y ^ ((c << 7) & mask)
        e = y ^ ((d << 7) & mask)

        return e

    @staticmethod
    def untemperD(y):
        a = y >> 11
        b = y ^ a
        c = b >> 11
        return y ^ c

    # // Generate the next n values from the series x_i
    # function twist() {
    #  for i from 0 to (n-1) {
    #      int x := (MT[i] and upper_mask)
    #                + (MT[(i+1) mod n] and lower_mask)
    #      int xA := x >> 1
    #      if (x mod 2) != 0 { // lowest bit of x is 1
    #          xA := xA xor a
    #      }
    #      MT[i] := MT[(i + m) mod n] xor xA
    #  }
    #  index := 0
    # }

    def twist(self):
        for index in range(0, 624):
            x = (self.mt[index] & self.upper_mask) + \
                (self.mt[(index + 1) % self.n] & self.lower_mask)
            xA = x >> 1
            if (x % 2) != 0:
                xA ^= self.a

            self.mt[index] = self.mt[(index + self.m) % self.n] ^ xA

        self.index = 0


