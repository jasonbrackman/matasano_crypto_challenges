"""
Detect single-character XOR
One of the 60-character strings in this file has been encrypted by single-character XOR.

Find it.

(Your code from #3 should help.)
"""
import single_byte_xor_cypher as sbxc

with open("4.txt", 'r') as handle:
    for line in handle.readlines():
        #print(line)
        sbxc.find_key_and_decrypt_message(line.strip())