import base64
import binascii
import cryptopals


def website_post():
    """
    The following code was found on:
    http://ropgadget.com/
    """
    testing = """
    56 32 68 35 51 58 4a 6c 57 57 39 31 55 6d 56 68
    5a 47 6c 75 5a 31 52 6f 61 58 4d 2f 56 47 68 6c
    55 47 46 7a 63 33 64 76 63 6d 52 47 62 33 4a 55
    61 47 56 61 61 58 42 47 61 57 78 6c 53 58 4e 55
    61 47 56 47 62 33 56 79 55 32 56 6a 64 47 6c 76
    62 6e 4e 54 59 57 35 7a 55 33 6c 74 59 6d 39 73
    4c 6b 56 75 61 6d 39 35 51 57 78 73 54 32 5a 4e
    65 55 35 76 64 47 56 7a 4c 6c 52 6f 5a 58 6c 4e
    59 58 6c 43 5a 55 6c 75 59 57 4e 6a 64 58 4a 68
    64 47 55 75 56 47 68 6c 65 55 31 68 65 55 4a 6c
    54 32 78 6b 4c 6b 64 70 62 6e 6c 31 52 6d 39 79
    59 32 56 53 64 57 78 36 4c 6b 5a 31 59 32 74 5a
    62 33 56 44 61 47 46 79 61 6b 5a 76 63 6b 4a 6c
    59 57 4e 6f 61 57 35 6e 56 47 68 6c 51 32 46 79
    63 6d 6c 6c 63 69 35 47 63 6d 56 6c 53 32 46 53
    64 46 52 76 54 32 34 75 54 45 39 4d 4c 67 3D 3D""".split()
    x = ''.join(testing)
    y = [binascii.unhexlify(key) for key in testing]
    z = b''.join(y)
    print(base64.b64decode(z).decode().replace(".", ".\n"))


def grouse_mountain():

    # clicking on my Grouse Grind image produced this
    other = b'W1siZiIsIjIwMTUvMDUvMDkvMTMvNDYvNDgvNTIyLzc4ZjRmNTNjZWZlM2YzNjZiMzBhNjJkZTJhODc2NWQ2Il0sWyJwIiwidGh1bWIiLCI4OXgxMjIjIl1d'
    other = b'W1siZiIsIjIwMTYvMDUvMTgvMTMvMjYvNDMvOTQ0L2ZsaWdodDIwMTZfYmFja2dyb3VuZC5qcGciXSxbInAiLCJyZXNpemVfYW5kX2Nyb3AiLHsid2lkdGgiOjE0MDAsImhlaWdodCI6MTAwMCwiZ3Jhdml0eSI6Im5lIn1dLFsiZSIsImpwZyIsIi1xdWFsaXR5IDgwIl1d'
    other = b'W1siZiIsIjIwMTYvMDQvMjkvMTUvNDcvNTgvMTM0L1NlZWtUaGVQZWFrX0JhY2tncm91bmQuanBnIl0sWyJwIiwicmVzaXplX2FuZF9jcm9wIix7IndpZHRoIjoxNDAwLCJoZWlnaHQiOjEwMDAsImdyYXZpdHkiOiJuZSJ9XSxbImUiLCJqcGciLCItcXVhbGl0eSA4MCJd'
    # converting base64 to binary produces the following (which looks like a structure):
    # b'[["f","2015/05/09/13/46/48/522/78f4f53cefe3f366b30a62de2a8765d6"],["p","thumb","89x122#"]]'
    print(binascii.a2b_base64(other))

    # The long hash looks like it might be something interesting?
    message = b"78f4f53cefe3f366b30a62de2a8765d6"
    unhexed = binascii.unhexlify(message)
    print("Message Length: {}".format(len(unhexed)))
    print("As Chars: {}".format(''.join([chr(itm) for itm in unhexed])))
    # tests say its not AES
    print("ECB?: {}".format(cryptopals.detect_ecb_use(message, 16)))
    print("XOR DECRYPTION? {}".format(cryptopals.find_key_and_decrypt_fixed_xor(message)))
    # is this XOR'd?
    key = cryptopals.break_repeating_key_xor(message)

    # seems like it may just be nonsense.
    print("Key?: {}".format(key))
    print("XOR DECRYPTION2: {}".format(cryptopals.decrypt_xor(message, key)))

    # reeoncde to request a larger image
    bigger = b'[["f","2015/05/09/13/46/48/522/78f4f53cefe3f366b30a62de2a8765d6"],["p","thumb","280x444#"]'
    bigger = binascii.b2a_base64(bigger)
    print("MODIFIED: {}".format(bigger))

    # NOTE: Changing 'p' to 'q' -- produces an error message 'Not Found'
    # NOTE: Changing the image size will change the size of the image -- but still loads the same image.
    # NOTE: Changing the 'thumb' to 'thumb2' produces no error, just a blank page.

if __name__ == "__main__":
    website_post()
    grouse_mountain()