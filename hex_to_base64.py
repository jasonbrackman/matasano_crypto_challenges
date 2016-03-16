
import binascii


def convert_bytes_to_base64(input_string):
    _hex = binascii.unhexlify(input_string)
    _b64 = binascii.b2a_base64(_hex)
    return _b64

if __name__ == "__main__":
    input_string = b"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    print(binascii.unhexlify(input_string))
    x = convert_bytes_to_base64(input_string)
    result = True if x.strip() == b"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t" else False
    print(result)


