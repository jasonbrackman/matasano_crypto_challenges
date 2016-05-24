import string
import random
import binascii
import base64
from operator import itemgetter
import itertools
import collections
from Crypto.Cipher import AES
import os

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


def decrypt_xor(data: bytes, key: bytes) -> bytes:
    # input = binascii.unhexlify(input)
    keys = itertools.cycle(key)

    a3 = bytes(x ^ y for (x, y) in zip(data, keys))

    return a3


def encrypt_xor(input: bytes, key: bytes):
    # ensure we are working with bytes
    if type(input) == str:
        input = bytes(input, 'ascii')

    keys = itertools.cycle(key)

    output = bytes([x ^ y for (x, y) in zip(input, keys)])

    return binascii.hexlify(output)


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


def detect_ecb_use(text, keysize: int):
    """
    If I understand this correctly - a large enough dataset will likely have something repeated since
    ECB is stateless and deterministic.
    """
    chunks = [text[n:n + keysize] for n in range(0, len(text), keysize)]
    if len(chunks) != len(set(chunks)):
        return True
    return False


def challenge_08():
    """
    8.txt contains a bunch of hex-encoded ciphertexts.
    - One of them has been encrypted with ECB.
    - Detect it.
    - The problem with ECB is that it is stateless and deterministic;
    - the same 16 byte plaintext block will always produce the same 16 byte ciphertext.
    """

    with open("8.txt", 'r') as handle:
        lines = handle.readlines()
        for ln, line in enumerate(lines):
            text = binascii.unhexlify(line.strip('\n'))
            if detect_ecb_use(text, 16):
                print(ln, line)


def pkcs_7_padding(text: bytes, pad: int) -> list:
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
            block += hexed * padding
        results.append(block)

    return results


def challenge_09():
    text = b'YELLOW SUBMARINE'
    print(pkcs_7_padding(text, 20))


def encrypt_aes_with_custom_cbc(text, key, iv):
    results = []
    keysize = len(key)
    blocks = [text[n:n + keysize] for n in range(0, len(text), keysize)]
    for block in blocks:
        padded_block = pkcs_7_padding(block, keysize)[0]
        xor_encrypt = encrypt_xor(padded_block, iv)
        unhexed = binascii.unhexlify(xor_encrypt)
        encrypt = encrypt_aes(unhexed, key)
        iv = encrypt
        results.append(encrypt)

    return results


def decrypt_aes_with_custom_cbc(text, key, iv):
    results = []
    keysize = len(key)
    blocks = [text[n:n + keysize] for n in range(0, len(text), keysize)]

    for block in blocks:
        aes_decrypt = decrypt_aes(block, key)
        xor_decrypt = decrypt_xor(aes_decrypt, iv)

        results.append(xor_decrypt)

        iv = block

    return results


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
    iv = bytes([0] * 16)
    test_text = b"this is my fancy text statement."
    encrypted = encrypt_aes(test_text, key)
    decrypted = decrypt_aes(encrypted, key)

    assert test_text == decrypted

    text = binascii.a2b_base64(open('10.txt', 'r').read())

    results = decrypt_aes_with_custom_cbc(text, key, iv)
    encrypt = encrypt_aes_with_custom_cbc(b"".join(results), key, iv)

    assert text == b"".join(encrypt)


def generate_random_bytes(length):
    return os.urandom(length)


def challenge_11():
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

    def encrypt_oracle(text):
        random_aes_key = generate_random_bytes(16)
        prefix = generate_random_bytes(random.randint(5, 10))
        postfix = generate_random_bytes(random.randint(5, 10))

        message = b"".join([prefix, text, postfix])

        if random.randint(1, 2) == 2:
            type = 'ECB'
            # encrypt ECB
            keysize = len(random_aes_key)
            blocks = [text[n:n + keysize] for n in range(0, len(text), keysize)]
            encrypted = []
            for block in blocks:
                padded_block = pkcs_7_padding(block, keysize)[0]
                text = encrypt_aes(padded_block, random_aes_key)
                # print(binascii.hexlify(text))
                encrypted.append(text)
        else:
            # encrypt_CBC
            type = 'CBC'
            random_iv = generate_random_bytes(16)
            encrypted = encrypt_aes_with_custom_cbc(message, random_aes_key, random_iv)

        return encrypted, type

    for x in range(10):
        test, type = encrypt_oracle(b"""This is a long story of two people who don't know each other, but something
        imortant needs to be told.  There once was a witch who lived in a shoe and she didn't have kids and didn't know
        what to do - but you know it was probably pretty important for her to do the things that she did cuz they told
        so many stories about her. Barbeques can be fun they tell me.  Is there nothing repeatable in this story? The
        only hting I have left is some additional words. What the hell should i do now -- cuz this is a long as heck
        story. This is something that is alrady a fairly good length -- it is hard for me to believe that shorter
        messages aren't going to be sent.  I guess if you are publishing a manifesto or something then the problem
        occurs. I mentioned a witch and some dogs and some kids.  Does that help? Tell me what I should do? Holy hell.
        What else must I do to prove that there is some repetition in the file? this seems pretty useless.

        This is a very long story of two people who don't know each other, but something important needs to be told.
        There once shoe and she didn't have kids and didn't know what to do. Something repeatable some random stuff
        was a witch who lived in a shoe and she didn't have kids and didn't know what to do. Something repeatable has to
        exist here or there simply won't be a way to determine if the text is repeating since it is stateless and
        deterministic. So now I'm just rambling on and on and figuring out what I should write -- but gotta admit this is
        prety crazy now.  I don't remember ever having to write an email of this length -- so if this is the weakness,
        then we are in a lot of trouble.One thing - is there a way to prevent it from dictating the directory - I set
        up all my substance directories within my Max project folders. Each object has it's own folder within the main
        substance folder - that's always been my workflow. But with this bridge it insists on creating a SendtoSubstance
        folder with an additional folder (exported name) with in that one. I would like to be able to just direct the
        files to the folder of my chosing. Now I have to move them then delete the SendtoSubstance folder.""")
        testing = b''.join(test)

        testing = binascii.hexlify(testing)
        print("Content encrypted as {0}.  Is ECB?: {1}".format(type, detect_ecb_use(testing, len(test[0]))))

        # print(test)


def encrypt_ecb_oracle(text, prefix, random_aes_key):
    message = b"".join([text, prefix])

    # encrypt ECB
    keysize = len(random_aes_key)
    blocks = [message[n:n + keysize] for n in range(0, len(message), keysize)]
    encrypted = []
    for block in blocks:
        padded_block = pkcs_7_padding(block, keysize)[0]
        _text = encrypt_aes(padded_block, random_aes_key)
        # print(binascii.hexlify(_text))
        encrypted.append(_text)

    return encrypted


def discover_block_size_and_if_ecb(encrypted_blocks):
    encrypted_string = b''.join(encrypted_blocks)
    key_length = get_secret_key_length_from_encrypted_data(encrypted_string)
    print("Number of blocks: {}".format(len(encrypted_blocks)))
    is_ecb = detect_ecb_use(encrypted_string, key_length)

    return key_length, is_ecb


def decrypt_ecb_message_without_key(encrypted_blocks, base64_decoded, random_aes_key):
    # Create encrypted content
    text_large = b'A' * 512
    encr_large = encrypt_ecb_oracle(text_large, base64_decoded, random_aes_key)
    key_length, is_ecb = discover_block_size_and_if_ecb(encr_large)
    print("Key Length: {0}\nIs ECB: {1}\n".format(key_length, is_ecb))

    collector = list()

    for block_idx in range(len(encrypted_blocks)):
        block_text = b'A' * key_length * block_idx

        current_block = list()
        for length in reversed(range(key_length)):
            text = block_text + b'A' * length  # one block short

            result = encrypt_ecb_oracle(text, base64_decoded[block_idx * 16:], random_aes_key)

            decrypted_block = b''.join(current_block)
            _decrypted = False

            for index in range(0, 255):
                if _decrypted is False:

                    text2 = b''.join([text, decrypted_block, chr(index).encode()])

                    if len(text2) <= key_length + len(block_text):

                        result2 = encrypt_ecb_oracle(text2, base64_decoded, random_aes_key)

                        if block_idx < len(encrypted_blocks) and result[block_idx] == result2[block_idx]:
                            current_block.append(chr(index).encode())
                            # print(block_idx, len(text2), chr(index), result2[block_idx])
                            _decrypted = True

        collector.append(b"".join(current_block))
    print("Decrypted: {}".format(b''.join(collector)))


def challenge_12():
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

    base64_encoded = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
    base64_decoded = base64.b64decode(base64_encoded)
    random_aes_key = generate_random_bytes(16)

    encrypted_blocks = encrypt_ecb_oracle(b'', base64_decoded, random_aes_key)

    decrypt_ecb_message_without_key(encrypted_blocks, base64_decoded, random_aes_key)


def challenge_13():
    """
    ECB cut-and-paste
    Write a k=v parsing routine, as if for a structured cookie. The routine should take:

    foo=bar&baz=qux&zap=zazzle
    ... and produce:

    {
      foo: 'bar',
      baz: 'qux',
      zap: 'zazzle'
    }
    (you know, the object; I don't care if you convert it to JSON).
    :return:
    """

    def create_structured_cookie(text):
        kv = collections.OrderedDict()
        items = text.split('&')
        for item in items:
            stuff = item.split('=')
            kv[stuff[0]] = stuff[1]

        return kv

    def profile_for(email):
        '''
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
        '''

        # Eat illegals
        illegals = '&='
        for illegal in illegals:
            email.replace(illegal, '')

        user_profile = collections.OrderedDict()
        user_profile['email'] = email
        user_profile['uid'] = 10
        user_profile['role'] = 'user'

        items = ['{0}={1}'.format(k, v) for k, v in user_profile.items()]
        user_text = '&'.join(items)

        return user_text

    email = 'adminisfake.test@gmail.com' + \
            'admin{}'.format('\x11' * 11) + \
            '   '  # necessary to push 'user' to its own line
    profile = profile_for(email)
    cookie = create_structured_cookie(profile)

    print(cookie)

    '''
    Now, two more easy functions. Generate a random AES key, then:
        A.	Encrypt the encoded user profile under the key; "provide" that to the "attacker".
        B.	Decrypt the encoded user profile and parse it.

    Using only the user input to profile_for() (as an oracle to generate "valid" ciphertexts)
    and the ciphertexts themselves, make a role=admin profile.
    '''
    random_aes_key = generate_random_bytes(16)

    blocks = pkcs_7_padding(profile.encode(), len(random_aes_key))
    blocks_as_string = b''.join(blocks)
    for_attacker = encrypt_aes(blocks_as_string, random_aes_key)

    print("For Attacker: {}".format(for_attacker))

    _ = pkcs_7_padding(for_attacker, len(random_aes_key))

    # Reorder the ECB Blocks and throw away the regular user account :)
    final = list()
    final.append(_[0])
    final.append(_[1])
    final.append(_[3])
    final.append(_[2])

    for_me = decrypt_aes(b''.join(final), random_aes_key)
    print("\n{}".format(for_me))


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
    challenge_11()
    challenge_12()
    challenge_13()
