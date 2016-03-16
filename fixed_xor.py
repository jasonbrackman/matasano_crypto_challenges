"""
http://cryptopals.com/sets/1/challenges/2/
1c0111001f010100061a024b53535009181c
... after hex decoding, and when XOR'd against:

686974207468652062756c6c277320657965
... should produce:

746865206b696420646f6e277420706c6179
"""


def decrypt(input, key):

    a1 = bytes.fromhex(input)
    a2 = bytes.fromhex(key)
    a3 = ""
    if len(input) == len(key):
        a3 = bytes([x ^ y for (x, y) in zip(a1, a2)])
    elif len(a2) == 1:
        padded_list = a2*len(a1)
        #print(padded_list)
        a3 = bytes([x ^ y for (x, y) in zip(a1, padded_list)])

    return a3.hex()

if __name__ == "__main__":

    data = "1c0111001f010100061a024b53535009181c"
    key  = "686974207468652062756c6c277320657965"

    print(decrypt(data, key))
