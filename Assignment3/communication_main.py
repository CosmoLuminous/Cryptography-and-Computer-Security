import argparse
import re
import sys
import time
from itertools import cycle
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


#from Cryptodome.Cipher import AES

KEY_LENGTH = 16
BLOCK_SIZE = 16
print("block size", BLOCK_SIZE)
key_aes = b"V38lKILOJmtpQMHp"
print(key_aes)

class AES_CIPHER:

    def _add_padding(message):
        


