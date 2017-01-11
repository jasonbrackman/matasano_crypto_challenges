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


def friends():
    # https: // grouse_services.fingerfoodapi.com / friends?user_id = 206092
    jd = b"W1siZiIsIjIwMTUvMDUvMjUvMTEvNTQvMjgvNzc0LzA3YmIzNDZlYTI3NzQ2NWE4ODc4MzQ0MGI0ODE5NmQzIl0sWyJwIiwidGh1bWIiLCI3NXg3NSMiXSxbImUiLCJqcGciXV0=="
    lb = b'W1siZiIsIjIwMTYvMDUvMTUvMjAvMzMvNDgvODAvYjI0ZDQ4YTFmYjFhMjc3ZGNkMWI3MzY5NDAwNjFhN2MiXSxbInAiLCJ0aHVtYiIsIjI3NXgyNzUjIl0sWyJlIiwianBnIl1d'
    print(base64.b64decode(lb))
    print(base64.b64decode(jd))
    #print(base64.b64decode(bb).decode())


def malware_class():
    import io
    from Crypto import Random

    payload = b'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'

    this = b"""import os
        def is_infected(filename):"""

    data = base64.b64decode(payload)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(io.BytesIO(this).read(24), AES.MODE_CFB, iv)

    print(cipher.decrypt(data)[16:])


if __name__ == "__main__":
    # website_post()
    # grouse_mountain()
    friends()
