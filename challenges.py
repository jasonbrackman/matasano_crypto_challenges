import random
import string
import time
import binascii
import collections
import cryptopals


def time_it(method):
    """
    Timing wrapper to log how long a method took to run.
    Example:
        @time_it
        def some_func():
            ...

    :param method: Expects to wrap a function
    :return:
    """

    def wrapper(*args, **kw):
        startTime = int(round(time.time() * 1000))
        result = method(*args, **kw)
        endTime = int(round(time.time() * 1000))
        print("Function Name: {0} - {1}ms".format(method.__name__, endTime - startTime))

        return result

    return wrapper


@time_it
def challenge_01() -> None:
    input_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    _hex = bytes.fromhex(
        input_string
    )  # b"I'm killing your brain like a poisonous mushroom"
    _b64 = binascii.b2a_base64(_hex).decode()

    assert (
        _b64.strip()
        == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    )


@time_it
def challenge_02() -> None:
    key = bytes.fromhex("686974207468652062756c6c277320657965")
    message = bytes.fromhex("1c0111001f010100061a024b53535009181c")

    decrypted = cryptopals.decrypt_xor(message, key)  # b"the kid don't play"

    assert decrypted == bytes.fromhex("746865206b696420646f6e277420706c6179")


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
    data = bytes.fromhex(
        "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    )
    key, decrypted_message = cryptopals.find_key_and_decrypt_fixed_xor(data)
    assert decrypted_message == b"Cooking MC's like a pound of bacon"


@time_it
def challenge_04() -> None:
    """
    Detect single-character XOR
    One of the 60-character strings in this file has been encrypted by single-character XOR.

    Find it.

    (Your code from #3 should help.)
    """

    with open("data/4.txt", "r") as handle:
        for line in handle.readlines():
            line = binascii.a2b_hex(line.strip())

            key, decrypted = cryptopals.find_key_and_decrypt_fixed_xor(line)

            if cryptopals.english.part_of_language(decrypted):
                assert decrypted == b"Now that the party is jumping\n"


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

    test = (
        b"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"
        b"a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    )
    line = (
        b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    )

    encrypt = cryptopals.encrypt_xor(line, b"ICE")
    assert encrypt == test


@time_it
def challenge_06() -> None:
    """
    Break repeating-key XOR
    :return:
    """
    with open("data/6.txt", "r") as handle:
        message = handle.read()

        # convert from base64 to bytes
        message = binascii.a2b_base64(message)

    result = cryptopals.break_repeating_key_xor(message)

    assert result == b"Terminator X: Bring the noise", result


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

    key = b"YELLOW SUBMARINE"

    with open("data/7.txt", "r") as handle:
        text = binascii.a2b_base64(handle.read())

        result = cryptopals.decrypt_aes(text, key)

        lines = result.decode("utf-8").split("\n")
        assert (
            lines[0] == "I'm back and I'm ringin' the bell "
        ), "Decrypt AES Failed: {}".format(lines[0])


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

    with open("data/8.txt", "r") as handle:
        lines = handle.readlines()

    for index, line in enumerate(lines):
        text = bytes.fromhex(line.strip("\n"))

        if cryptopals.detect_ecb_use(text, 16):
            break

    assert ecb_encrypted_line == index


@time_it
def challenge_09() -> None:
    text = b"YELLOW SUBMARINE"
    assert b"YELLOW SUBMARINE\x04\x04\x04\x04" == cryptopals.pkcs_7_padding(text, 20)


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
    key = b"YELLOW SUBMARINE"
    iv = bytes([0] * 16)
    test_text = b"this is my fancy text statement."
    encrypted = cryptopals.encrypt_aes(test_text, key)
    decrypted = cryptopals.decrypt_aes(encrypted, key)

    assert test_text == decrypted

    text = binascii.a2b_base64(open("data/10.txt", "r").read())

    results = cryptopals.decrypt_aes_with_custom_cbc(text, key, iv)
    results = cryptopals.pkcs_7_padding_verification(b"".join(results))
    # print(b''.join(results))
    # print(results_stripped)

    blocks = cryptopals.encrypt_aes_with_custom_cbc(results, key, iv)

    assert text == b"".join(blocks), "{}".format(blocks)


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
        random_aes_key = cryptopals.generate_random_bytes(16)
        prefix = cryptopals.generate_random_bytes(random.randint(5, 10))
        postfix = cryptopals.generate_random_bytes(random.randint(5, 10))

        message = b"".join([prefix, text, postfix])

        if random.randint(1, 2) == 2:
            encoding_type = "ECB"
            # encrypt ECB
            keysize = len(random_aes_key)
            text = cryptopals.pkcs_7_padding(text, keysize)
            blocks = [text[n : n + keysize] for n in range(0, len(text), keysize)]
            encrypted = []
            for block in blocks:
                text = cryptopals.encrypt_aes(block, random_aes_key)
                # print(binascii.hexlify(text))
                encrypted.append(text)
        else:
            # encrypt_CBC
            encoding_type = "CBC"
            random_iv = cryptopals.generate_random_bytes(16)
            encrypted = cryptopals.encrypt_aes_with_custom_cbc(
                message, random_aes_key, random_iv
            )

        return encrypted, encoding_type

    for x in range(10):
        test, is_ecb = encrypt_oracle(b"A" * 212)
        testing = b"".join(test)

        testing = binascii.hexlify(testing)
        assert (is_ecb == "ECB") == cryptopals.detect_ecb_use(testing, len(test[0]))
        # print("Content encrypted as {0}.  Is ECB?: {1}".format(is_ecb, detect_ecb_use(testing, len(test[0]))))

        # print(test)


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
    base64_encoded = (
        "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGll"
        "cyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
    )
    base64_decoded = binascii.a2b_base64(
        base64_encoded
    )  #  base64.b64decode(base64_encoded)
    random_aes_key = cryptopals.generate_random_bytes(16)

    encrypted_blocks = cryptopals.encrypt_ecb_oracle(
        b"", base64_decoded, random_aes_key
    )

    result = cryptopals.decrypt_ecb_message_without_key(
        encrypted_blocks, base64_decoded, random_aes_key
    )

    assert (
        result
        == b"Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby"
        b" waving just to say hi\nDid you stop? No, I just drove by\n\x01"
    ), "Decryption Failed!"


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
        illegals = "&="
        for illegal in illegals:
            user_input.replace(illegal, "")

        user_profile = collections.OrderedDict()
        user_profile["email"] = user_input
        user_profile["uid"] = 10
        user_profile["role"] = "user"

        items = ["{0}={1}".format(k, v) for k, v in user_profile.items()]
        user_text = "&".join(items)

        return user_text

    email = (
        "theadminisfake.test@gmail." + "admin{}".format("\x11" * 11) + "com"
    )  # necessary to push 'user' to its own line
    profile = profile_for(email)
    cookie = cryptopals.create_structured_cookie(profile)

    # print(cookie)

    """
    Now, two more easy functions. Generate a random AES key, then:
        A.	Encrypt the encoded user profile under the key; "provide" that to the "attacker".
        B.	Decrypt the encoded user profile and parse it.

    Using only the user input to profile_for() (as an oracle to generate "valid" ciphertexts)
    and the ciphertexts themselves, make a role=admin profile.
    """
    random_aes_key = cryptopals.generate_random_bytes(16)
    keysize = len(random_aes_key)
    message = cryptopals.pkcs_7_padding(profile.encode(), keysize)
    for_attacker = cryptopals.encrypt_aes(message, random_aes_key)

    # print("For Attacker: {}".format(for_attacker))

    # to_be_swizzled = pkcs_7_padding(for_attacker, len(random_aes_key))
    to_be_swizzled = [
        for_attacker[n : n + keysize] for n in range(0, len(for_attacker), keysize)
    ]
    # Reorder the ECB Blocks and throw away the regular user account :)
    final = list()
    final.append(to_be_swizzled[0])
    final.append(to_be_swizzled[1])
    final.append(to_be_swizzled[3])
    final.append(to_be_swizzled[2])

    for_me = cryptopals.decrypt_aes(b"".join(final), random_aes_key)

    assert (
        for_me == b"email=theadminisfake.test@gmail.com&uid=10&"
        b"role=admin\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11"
    ), "Admin account could not be hacked!"


@time_it
def challenge_14() -> object:
    """
    Take your oracle function from #12. Now generate a random count of random bytes and prepend this string to every
    plaintext. You are now doing:

    AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)

    :return:
    """

    base64_encoded = (
        "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGll"
        "cyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
    )
    base64_decoded = binascii.a2b_base64(base64_encoded)
    random_aes_key = cryptopals.generate_random_bytes(16)
    random_prepend = cryptopals.generate_random_bytes(random.randint(1, 15))
    encrypted_blocks = cryptopals.encrypt_ecb_oracle(
        b"", base64_decoded, random_aes_key, prepend=random_prepend
    )

    # print("Padding: {}".format(obtain_ecb_pkcs7_count(base64_decoded, random_aes_key, prepend=random_prepend)))
    cryptopals.obtain_ecb_prepend_padding_count(
        base64_decoded, random_aes_key, prepend=random_prepend
    )
    # print(decrypt_aes(b''.join(encrypted_blocks), random_aes_key))
    # print("Original Encrypted Blocks: {}".format(len(encrypted_blocks)))

    result = cryptopals.decrypt_ecb_message_without_key(
        encrypted_blocks, base64_decoded, random_aes_key, prepend=random_prepend
    )
    assert base64_decoded == result.strip(
        b"\x01"
    ), "Decryption failed! {} != {}".format(base64_decoded, result)


@time_it
def challenge_15() -> None:
    tests = [
        b"ICE ICE BABY\x04\x04\x04\x04",
        b"ICE ICE BABY\x05\x05\x05\x05",
        b"ICE ICE BABY\x01\x02\x03\x04",
        b"I\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f",
        b"YELLOW SUBMARINE",
    ]

    expected_results = [b"ICE ICE BABY", b"I", b"YELLOW SUBMARINE"]

    received_results = list()
    for test in tests:
        try:
            received_results.append(cryptopals.pkcs_7_padding_verification(test))
        except ValueError:
            pass

    for item in received_results:
        assert item in expected_results, "PKCS7 Padding Verification Failed."


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
        cleaned = message.replace(";", "").replace("=", "")
        append = r";comment2=%20like%20a%20pound%20of%20bacon"

        full_message = "{}{}{}".format(prepend, cleaned, append).encode()

        encrypted = cryptopals.encrypt_aes_with_custom_cbc(
            full_message, key, b"YELLOW SUBMARINE"
        )

        return encrypted

    def is_admin(encrypted, random_aes_key):

        decrypted = cryptopals.decrypt_aes_with_custom_cbc(
            b"".join(encrypted), random_aes_key, b"YELLOW SUBMARINE"
        )
        # print('FUN: {}'.format(decrypted[2]))
        return False if b"".join(decrypted).find(b";admin=true;") == -1 else True

    random_aes_key = cryptopals.generate_random_bytes(16)
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
        iv = cryptopals.generate_random_bytes(16)
        key = cryptopals.generate_random_bytes(16)
        test_data = [
            b"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc =",
            b"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic =",
            b"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw ==",
            b"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg ==",
            b"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
            b"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA ==",
            b"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw ==",
            b"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8 =",
            b"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g =",
            b"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
        ]

        def get_encrypted_blocks(self):
            # The first function should
            # - select at random one of ten strings
            # - generate a random AES key (which it should save for all future encryptions),
            # - pad the string out to the 16-byte AES block size and
            # - CBC-encrypt it under that key,
            # - providing the caller the ciphertext and IV.

            # grab a random string
            random_string = self.test_data[random.randrange(0, len(self.test_data))]

            print("-" * 128)
            print("PRIOR TO ENCRYPTION: {}".format(random_string))
            print("PRIOR TO ENCRBASE64: {}".format(binascii.a2b_base64(random_string)))

            # encrypt using CBC
            encrypted_blocks = cryptopals.encrypt_aes_with_custom_cbc(
                random_string, self.key, self.iv
            )

            return encrypted_blocks

        def decrypt_cookie(self, ciphertext):
            # Consume the ciphertext
            # decrypt it,
            # check its padding, and
            # return true or false depending on whether the padding is valid.
            blocks = cryptopals.decrypt_aes_with_custom_cbc(
                ciphertext, self.key, self.iv
            )
            message = b"".join(blocks)
            # print("{} (Decrypted)".format(message))

            try:
                cryptopals.pkcs_7_padding_verification(message)
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

            prefix = b"-" * (16 - slot)
            postfix = b""

            for counter, b1 in enumerate(byte_items, 1):
                postfix += bytes([b1 ^ slot])

            for index in range(0, 256):
                if found is False:
                    c1a = prefix + bytes([index]) + postfix
                    # print(c1a)
                    assert len(c1a) == 16, "Expected 16 bytes -- got {}".format(
                        len(c1a)
                    )

                    ciphertext = b"".join((c1a, c2))
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
                print("[FAILED] Was unable to find byte {} ....".format(17 - slot))
                final_results = [chr(result) for result in results]
                # print("STRING DECRYPTED: {}".format((b'.' * (17-slot)) + ''.join(final_results).encode()))
                print("server key: {}".format(server.key))
                print("server iv: {}".format(server.iv))
                return ([69] * (18 - slot)) + results

        return results

    results = []
    blocks.insert(0, server.iv)
    for c1, c2 in zip(blocks, blocks[1:]):
        result = side_channel_attack(c1, c2)
        if result:
            results.append("".join([chr(item) for item in result]))

    print("-" * 128)
    print("DECRYPTED: {}".format(results))
    print("DECBASE64: {}".format(binascii.a2b_base64("".join(results))))
    print("-" * 128)


@time_it
def challenge_18():
    """
    key = YELLOW SUBMARINE
    nonce = 0
    format = 64 bit unsigned little endian nonce, 64 bit little endian block count(byte count / 16)
    """

    key = b"YELLOW SUBMARINE"
    ctr_encrypted = (
        b"L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
    )
    ctr_encrypted = binascii.a2b_base64(ctr_encrypted)

    decrypted = cryptopals.aes_with_custom_ctr(ctr_encrypted, key, nonce=0)

    assert (
        decrypted == b"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "
    ), "CTR Decryption failed!"


@time_it
def challenge_19() -> None:
    """
    Attack this cryptosystem piecemeal: guess letters, use expected English language frequence to validate guesses,
    catch common English trigrams, and so on.
    :return:
    """
    lines = [
        "SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
        "Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
        "RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
        "RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
        "SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
        "T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
        "T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
        "UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
        "QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
        "T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
        "VG8gcGxlYXNlIGEgY29tcGFuaW9u",
        "QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
        "QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
        "QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
        "QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
        "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
        "VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
        "SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
        "SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
        "VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
        "V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
        "V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
        "U2hlIHJvZGUgdG8gaGFycmllcnM/",
        "VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
        "QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
        "VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
        "V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
        "SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
        "U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
        "U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
        "VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
        "QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
        "SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
        "VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
        "WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
        "SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
        "SW4gdGhlIGNhc3VhbCBjb21lZHk7",
        "SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
        "VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
        "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
    ]

    # Generate a random key and encrypt the above base64 text
    random_key = cryptopals.generate_random_bytes(16)
    encrypted_messages = []
    for item in lines:
        message = binascii.a2b_base64(item)
        encrypted = cryptopals.aes_with_custom_ctr(message, random_key, nonce=0)
        encrypted_messages.append(encrypted)

    """
    foo_BYTE XOR bar_BYTE = KEYSTREAM-BYTE
    And since the keystream is the same for every ciphertext:
    foo-BYTE XOR KEYSTREAM-BYTE = bar-BYTE
    """
    key = []
    max_line_length = len(max(encrypted_messages, key=len))
    for index in range(0, max_line_length):
        scores = {}
        for guess in range(256):

            items = [
                chr(message[index] ^ guess)
                for message in encrypted_messages
                if len(message) > index
            ]
            score = cryptopals.english.score_text("".join(items).encode())
            scores[guess] = score

        high_score = max(scores, key=lambda x: scores[x])
        if high_score > 0:
            key.append(bytes([high_score]))

    test_total_decrypt = []
    final_key = b"".join(key)
    keysize = len(final_key)
    for line, message in zip(lines, encrypted_messages):
        blocks = [message[n : n + keysize] for n in range(0, len(message), keysize)]
        decrypt = [cryptopals.decrypt_xor(block, final_key) for block in blocks]

        test_total_decrypt.append(
            cryptopals.compute_hamming_distance(
                b"".join(decrypt), binascii.a2b_base64(line)
            )
        )

    normalized_distance = sum(test_total_decrypt) / len(test_total_decrypt)
    assert (
        normalized_distance < 5
    ), "Hamming Distance of {} suggests decryption failed.".format(normalized_distance)
    # print(f"Decrypted with a Hamming Distance from known clear text of {normalized_distance}")


@time_it
def challenge_20() -> None:
    """
    Using 20.txt, find a similar set of Base64'd plaintext. Do with them exactly what you did with the first, but
    solve the problem differently.  Instead of making spot guesses at to known plaintext, treat the collection of
    ciphertexts the same way you would repeating-key XOR.

    Obviously, CTR encryption appears different from repeated-ke XOR, but with a fixed nonce they are effectively
    the same thing.

    To exploit this:
    1. take your collection of ciphertexts and
    2. truncate them to a common length (the length of the smallest ciphertext will work).

    Solve the resulting concatenation of ciphertexts as if for repeating- key XOR, with a key size of the length of
    the ciphertext you XOR'd.
    """
    key = cryptopals.generate_random_bytes(16)
    nonce = 0

    with open("data/20.txt", "r") as handle:
        lines = [binascii.a2b_base64(line.strip()) for line in handle.readlines()]
        crypts = [cryptopals.aes_with_custom_ctr(line, key, nonce) for line in lines]

    # min_length = len(max(crypts, key=len))
    blocks = [crypt for crypt in crypts]

    transposed = cryptopals.transpose(blocks)

    # check each index for possible hits
    # if more than one hit -- check for score.

    keys = {}
    for index, block in enumerate(transposed):
        keys[index] = []
        for guess in range(255):
            items = [(item ^ guess) for item in block]
            count = [
                item
                for item in items
                if chr(item) in (string.ascii_letters + " ,.'?:-;")
            ]
            # if index == 10:
            #    print(len(items), len(count), [chr(item) for item in items])

            keys[index].append([len(count), bytes([guess])])

    key = []
    for index in keys:
        key.append(max(keys[index], key=lambda x: x[0])[1])

    result = b"".join(key)
    print(result)

    for block in blocks:
        print(cryptopals.decrypt_xor(block, result))


@time_it
def challenge_21():
    """
    Implement the MT19937 Mersenne Twister RNG
    - https://en.wikipedia.org/wiki/Mersenne_Twister
    :return:
    """

    x = cryptopals.MT19337(90210)

    assert x.extract_number() == 826079627


@time_it
def challenge_22():
    """
    - Wait a random number of seconds between, I don't know, 40 and 1000.
    - Seeds the RNG with the current Unix timestamp
    - Waits a random number of seconds again.
    - Returns the first 32 bit output of the RNG.
    :return:
    """

    current_time = int(time.time())

    time.sleep(random.randint(10, 20))

    random_number = cryptopals.MT19337(current_time).extract_number()

    result = 0
    future_time = int(time.time())
    for index in range(1000):
        temp_time = future_time - index
        test_number = cryptopals.MT19337(temp_time).extract_number()
        if test_number == random_number:
            # print("Actual Seed: {}".format(current_time))
            # print("Derived Seed: {} (Found in {} iterations)".format(temp_time, index+1))
            result = temp_time
            break

    assert result == current_time


def challenge_23():
    """
    Task: Clone an MT19937 RNG from its output

    The internal state of MT19937 consists of 624 32 bit integers.

    For each batch of 624 outputs, MT permutes that internal state. By permuting state regularly, MT19937
    achieves a period of 2**19937, which is Big.

    Each time MT19937 is tapped, an element of its internal state is subjected to a tempering function that
    diffuses bits through the result.

    The tempering function is invertible; you can write an "untemper" function that takes an MT19937 output and
    transforms it back into the corresponding element of the MT19937 state array.

    ****
    To invert the temper transform, apply the inverse of each of the operations in the temper transform in reverse
    order. There are two kinds of operations in the temper transform each applied twice; one is an XOR against a
    right-shifted value, and the other is an XOR against a left-shifted value AND'd with a magic number. So you'll
    need code to invert the "right" and the "left" operation.
    ***

    Once you have "untemper" working, create a new MT19937 generator, tap it for 624 outputs, untemper each of them
    to recreate the state of the generator, and splice that state into a new instance of the MT19937 generator.

    The new "spliced" generator should predict the values of the original.
    """
    current_time = int(time.time())
    print("Current Time: ", current_time)
    MT = cryptopals.MT19337(current_time)
    random_number = MT.extract_number()
    random_number2 = MT.extract_number()
    print(random_number, random_number2)

    untemper = cryptopals.MT19337.untemper(random_number)

    print("\n")
    print("      seed:", current_time)
    print("  tempered:", random_number)
    print(" tempered2:", random_number2)
    print("unTempered:", untemper)
    spliced_mt = cryptopals.MT19337(untemper)
    rn_01 = spliced_mt.extract_number()
    rn_02 = spliced_mt.extract_number()

    assert random_number2 == rn_02

    pass


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
    challenge_18()
    challenge_19()
    challenge_20()
    challenge_21()

    challenge_22()
    challenge_23()
