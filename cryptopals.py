import binascii
from operator import itemgetter

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

keywords = ['the', 'be', 'to', 'of', 'and', 'in', 'that', 'have', 'it', 'for', 'not', 'on', 'with', 'he', 'as',
           'you', 'do', 'at', 'this', 'but', 'his', 'by', 'from', 'they', 'we', 'say', 'her', 'she', 'or', 'an', 'will',
           'my', 'one', 'all', 'would', 'there', 'their', 'what', 'so', 'up', 'out', 'if', 'about', 'who', 'get',
           'which', 'go', 'me', 'when', 'make', 'can', 'like', 'time', 'no', 'just', 'him', 'know', 'take', 'people',
           'into', 'year', 'your', 'good', 'some', 'could', 'them', 'see', 'other', 'than', 'then', 'now', 'look',
           'only', 'come', 'its', 'over', 'think', 'also', 'back', 'after', 'use', 'two', 'how', 'our', 'work', 'first',
           'well', 'way', 'even', 'new', 'want', 'because', 'any', 'these', 'give', 'day', 'most', 'us']


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
        key = bytes.fromhex(key)
    elif type(key) == int:
        key = key.to_bytes(2, 'big')

    output = ""
    if len(input) == len(key):
        output = bytes([x ^ y for (x, y) in zip(input, key)])
    elif len(key) == 1:
        padded_list = key*len(input)
        output = bytes([x ^ y for (x, y) in zip(input, padded_list)])

    return binascii.b2a_hex(output)


def score_text(decrypted):

    scores = []
    for item in decrypted.decode('utf-8').lower():

        try:
            scores.append(letters[item])

        except KeyError as e:
            scores.append(0.0)

    return sum(scores)


def find_key_and_decrypt_message(data, quiet=True):
    """
    Single-byte XOR cipher
    The hex encoded string:

    1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
    ... has been XOR'd against a single character. Find the key, decrypt the message.

    You can do this by hand. But don't: write code to do it for you.

    How? Devise some method for "scoring" a piece of English plaintext. Character frequency is a good metric.
    Evaluate each output and choose the one with the best score.
    """

    scores = list()
    for key in range(10, 100):
        try:
            decrypted_xor = decrypt_fixed_xor(data, binascii.a2b_hex(str(key)))
            decrypted = binascii.unhexlify(decrypted_xor)
            scores.append((key, score_text(decrypted), decrypted))

            """
            results = [item for item in decrypted.split() if item.decode('utf-8') in keywords]
            if results:
                print('Data: {}'.format(data))
                if not quiet:
                    print("Key in Hex: {}".format(key))
                    print("Key as byte: {}".format(binascii.unhexlify(str(key))))
                    print("Item: {}".format(results))
                    print("Decrypted Text: {}".format(decrypted))
                _key = key
                _decrypted = decrypted
            """
        except binascii.Error as e:
            print(key)
            pass
        except UnicodeDecodeError as e:
            pass
        except AttributeError as e:
            pass
    print(scores)
    _key, _, _decrypted = max(scores, key=itemgetter(1))

    return _key, _decrypted


def challenge_01():
    input_string = b"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    print(binascii.unhexlify(input_string))
    x = convert_bytes_to_base64(input_string)
    result = True if x.strip() == b"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t" else False
    print(result)


def challenge_02():
    data = "1c0111001f010100061a024b53535009181c"
    key  = "686974207468652062756c6c277320657965"

    decrypted = decrypt_fixed_xor(data, key)
    print(binascii.unhexlify(decrypted))
    assert decrypted == b'746865206b696420646f6e277420706c6179'


def challenge_03():
    data = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    print(find_key_and_decrypt_message(data))


if __name__ == "__main__":
    challenge_01()
    challenge_02()
    challenge_03()

