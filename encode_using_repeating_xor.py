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
import binascii
import itertools


def decrypt_xor(input, key):

    input = binascii.unhexlify(input)
    keys = itertools.cycle(key)

    a3 = bytes(x ^ y for (x, y) in zip(input, keys))

    return a3

def encrypt_xor(input, key):
    # ensure we are working with bytes
    if type(input) == str:
        input = bytes(input, 'ascii')

    keys = itertools.cycle(key)

    output = bytes([x ^ y for (x, y) in zip(input, keys)])

    return binascii.hexlify(output)

def test_001():
    line = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    result = encrypt_xor(line, b"ICE")
    print(result)
    test = b"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    assert result == test

def test_002():
    line = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    line = b"whatever, man.  Boom!!"
    encrypt = encrypt_xor(line, b"ICE")
    decrypt = decrypt_xor(encrypt, b"ICE")
    print(line == decrypt)

if __name__ == "__main__":
    test_002()