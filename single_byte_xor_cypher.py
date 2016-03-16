"""
Single-byte XOR cipher
The hex encoded string:

1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
... has been XOR'd against a single character. Find the key, decrypt the message.

You can do this by hand. But don't: write code to do it for you.

How? Devise some method for "scoring" a piece of English plaintext. Character frequency is a good metric.
Evaluate each output and choose the one with the best score.
"""
import binascii
import fixed_xor

keywords = ['the', 'be', 'to', 'of', 'and', 'in', 'that', 'have', 'it', 'for', 'not', 'on', 'with', 'he', 'as',
           'you', 'do', 'at', 'this', 'but', 'his', 'by', 'from', 'they', 'we', 'say', 'her', 'she', 'or', 'an', 'will',
           'my', 'one', 'all', 'would', 'there', 'their', 'what', 'so', 'up', 'out', 'if', 'about', 'who', 'get',
           'which', 'go', 'me', 'when', 'make', 'can', 'like', 'time', 'no', 'just', 'him', 'know', 'take', 'people',
           'into', 'year', 'your', 'good', 'some', 'could', 'them', 'see', 'other', 'than', 'then', 'now', 'look',
           'only', 'come', 'its', 'over', 'think', 'also', 'back', 'after', 'use', 'two', 'how', 'our', 'work', 'first',
           'well', 'way', 'even', 'new', 'want', 'because', 'any', 'these', 'give', 'day', 'most', 'us']

def find_key_and_decrypt_message(data):

    for key in range(0, 255):
        try:
            result = fixed_xor.decrypt(data, binascii.unhexlify(str(key)).hex())
            decrypted = bytes.fromhex(result)

            results = [item for item in decrypted.decode().split() if item in keywords]
            if results:
                print("Key in Hex: {}".format(key))
                print("Key as byte: {}".format(binascii.unhexlify(str(key))))
                print("Item: {}".format(results))
                print("Decrypted Text: {}".format(decrypted))
        except binascii.Error as e:
            pass
        except UnicodeDecodeError as e:
            pass

if __name__ == "__main__":
    data = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    find_key_and_decrypt_message(data)