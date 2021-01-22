#!/usr/bin/env python
# coding: utf-8

# In[2]:


'''
Author: Aman Bhardwaj
Date: 10 AUG 2020
Entry No. 2019SIY7580
'''

'''Import Modules'''
import argparse
import re
import sys
import time
from itertools import cycle
from Crypto.Cipher import AES
from Crypto import Random
import time

'''COLOR UNICODES FOR PRINTING COLORED TEXT IN TERMINAL'''
BLACK = '\033[30m'
RED = '\033[31m'
GREEN = '\033[32m'
YELLOW = '\033[33m'
BLUE = '\033[34m'
MAGENTA = '\033[35m'
CYAN = '\033[36m'
WHITE = '\033[37m'
UNDERLINE = '\033[4m'
RESET = '\033[0m'
BOLD    = "\033[;1m"
REVERSE = "\033[;7m"

'''Global variables AES CIPHER'''
KEY_LENGTH = 16
BLOCK_SIZE = AES.block_size
rand_generator = Random.new()
key_aes = rand_generator.read(KEY_LENGTH)
iv = rand_generator.read(KEY_LENGTH)



class CLIENT_AES:
    '''
    Class: CLIENT - Encrypts message by AES Cipher and get it ready to be transmitted via secured channel.
    
    This class encodes and encrypts the plain text message from the client and sends to the server via SSL/TLS.
    This class implements the following function:   
    '''

    def _pad(self, message):
        '''
        Function to complete the block size (16) for the message blocks. If in case the last block is shorter than
        16 Bytes then it adds padding as per PKCS7 Encoding guidelines.
        This enables HACKER/Man In The Middle to carry out Padding oracle attack.
        
        params:
        self: Class reference
        message: plain text message (Bytes)
        '''
        
        last_block_len = len(message) % BLOCK_SIZE
        bytes_to_pad = BLOCK_SIZE - last_block_len
        
        pad = bytes([bytes_to_pad]) * bytes_to_pad
        message += pad
        #print(message)
        return message
    
    def encrypt(self, message):
        '''
        Once the message has been encoded with PKCS7 guidelines. It is then encrypted here by AES128 CIPHER.
        MODE OF OPERATION: CBC - Cipher Block Chaining
        PRIVATE KEY: communicated b/w client and server during handshake.
        
        params:
        self: Class reference
        message: plain text message (Bytes) to encrypt
        
        return: Encrypted text
        '''
        
        aes_cipher = AES.new(key_aes, AES.MODE_CBC, iv)
        cipher_text = aes_cipher.encrypt(self._pad(message))
        return cipher_text
    
class SERVER_AES:       
    '''
    CLASS: SERVER - Receives the message via SSL/TLS and decrypts it by AES128 CIPHER.
    
    It implements the following functions:
    '''
    def _unpad(self, message):
        '''
        Function to remove the extra padding from the message once it has been decoded and retrieve the original 
        plain text. It follows PKCS% guidelines
        
        params:
        self: Class reference
        message: cipher text message (Bytes)
        '''
        padding_length = message[-1]
        if padding_length == 0 or padding_length > BLOCK_SIZE:
            return 0
        for i in range(1, padding_length):
            if message[-i-1] != padding_length:
                return 0
        return message[0 : -1*padding_length]
    
    def decrypt(self, message):
        '''
        Once the crypted message has been received via SSL/TLS. It is then decrypted here by AES128 CIPHER.
        MODE OF OPERATION: CBC - Cipher Block Chaining
        PRIVATE KEY: communicated b/w client and server during handshake.
        
        params:
        self: Class reference
        message: plain text message (Bytes) to decrypt
        
        return: Decrypted Text
        '''
        
        aes_cipher = AES.new(key_aes, AES.MODE_CBC, iv)
        plain_text = aes_cipher.decrypt(message)
        plain_text = self._unpad(plain_text)
        return plain_text
    
    def check_padding(self, message):
        '''
        This function checks if the message received from the client has been properly encoded with Block size 16
        as per PKCS5 Encoding.        
        
        params:
        self: Class reference
        message: crypted text message (Bytes)
        
        return: True if encoding is correct
                False if encoding is wrong
        '''
        if self.decrypt(message) != 0:
            return True
        else:
            return False
        
    
    
class PADDING_ORACLE_ATTACK:
    '''
    CLASS: PADDING ORACLE ATTACK
    This class implements function to initialize and facilitate Padding Oracle Attack by Man In The Middle.    
    
    '''
    
    def man_inthe_middle_init(self, en_text):
        '''
        Initialize Padding Oracle Attack:
        
        params:
        self: Class reference
        en_text: Intercepted crypted text message (Bytes)
        
        return: .
        '''
        
        print(RED+"\n\n")
        print("               ## ALICE-->------------->-----TO----->------------->---BOB ##")
        print("                                             ||")
        print("                                             ||")
        print("                                             ||")
        print("                                             ||")
        print("                                   ## MAN IN THE MIDDLE ##")
        print("                                  ## Message Intercepted ##\n")
        print(RED+"Intercepted Message:",RESET+CYAN, en_text)
        return

    def padding_oracle_attack(self, en_text):
        '''
        Implements Padding Oracle Attack:
        Exploits server's check_padding function and PKCS5 encoding if server doesn't have a firewall which blocks
        frequent calls from an IP Address.
        Here MITM Acts as a pseudo client and exploits the above vulnerability SSL/TLS security which uses AES Cipher
        operating in CBC Mode.
        
        params:
        self: Class reference
        en_text: Intercepted crypted text message (Bytes)        
        
        return: Cracked Cipher Text
        '''
        
        #initialize variables
        deciphered_message = ""
        current_idx = 0
        dummy_cipher = [0] * 16
        dummy_plain = [0] * 16
        
        #calculate Blocks in Message BLOCK_SIZE = 16
        total_blocks = len(en_text)/BLOCK_SIZE
        total_blocks = int(total_blocks) + 1 
        print(MAGENTA+"Total Blocks in Cipher Text ="+BLUE,total_blocks)
        server = SERVER_AES()
        
        #Create List of Message Blocks with iv as first block
        msg_blocks = [iv]
        for i in range(total_blocks):
            msg_blocks.append(en_text[i * BLOCK_SIZE: BLOCK_SIZE * (i+1)])
        
        
        #carry out Padding Oracle Attack
        for blk_idx in range(total_blocks-1):
            print(RED+"\n[+]---",RESET+MAGENTA+"Cracking Block Number:", BLUE, blk_idx)
            for byte_idx in range(1, BLOCK_SIZE+1, 1):
                for k in range(256):
                    dummy_cipher[-1*byte_idx] = k
                    
                    #Check for actual padding at the end and identify the Last Byte
                    mock_msg = bytes(dummy_cipher) + msg_blocks[blk_idx+1]
                    if server.check_padding(mock_msg):
                        
                        current_idx = byte_idx
                        dummy_plain[-1*byte_idx] = k^byte_idx^msg_blocks[blk_idx][-byte_idx]
                
                for j in range(1, current_idx+1):
                    dummy_cipher[-j] = dummy_plain[-j]^byte_idx+1^msg_blocks[blk_idx][-1*j]
            
            #Recreate decipher_message
            for l in range(BLOCK_SIZE):
                plain_byte = dummy_plain[l]
                if plain_byte >= 32:
                    deciphered_character = chr(int(plain_byte))                    
                    deciphered_message += deciphered_character
            time.sleep(0.4)
            print(BOLD+RED+"    Deciphered Block:", CYAN ,deciphered_message[-16:])
            hacked_msg = str.encode(deciphered_message)

        return hacked_msg


def _encrypt_message(aes, message):
    '''
    Init Encryption by AES128. CBC MODE
    '''
    print(YELLOW+"@@@------------MESSAGE FROM ALICE TO BOB-------------@@@")
    print(MAGENTA+"Plain Text:")
    print("Message:"+RESET+BLUE, message)
    time.sleep(1)
    print(BOLD+GREEN+"[+]---",RESET+GREEN+"Encrypting Message with AES128...")
    print(BOLD+GREEN+"[+]---",RESET+GREEN+"Mode of Operation = CBC(CIPHER BLOCK CHAINING).")
    print(BOLD+GREEN+"[+]---",RESET+GREEN+"CBC Block Size = 16 Bytes\n")
    time.sleep(1)
    cipher_text = aes.encrypt(message) #Call Encrypt function
    print(BOLD+MAGENTA+"Encrypted Cipher Text:",RESET+BLUE, cipher_text)
    print("\n")
    
    return cipher_text

def _send_message():
    '''
    Send Encrypted message via secured SSL/TLS Channel
    '''
    time.sleep(1)
    print(BOLD+GREEN+"%%%---SENDING..!!! CIPHER TEXT VIA AES128 SECURED CONNECTION...%%%")
    print(YELLOW+"## ALICE---------->-----------TO------------>---------BOB ##\n")
    return

def _decrypt_message(aes, c_text):
    '''
    Init Decryption by AES128. CBC MODE
    '''
    time.sleep(1)
    print(GREEN+"%%%-----------------MESSAGE RECEIVED..!!!-------------------%%%")
    print(YELLOW+"@@@---------------MESSAGE RECEIVED BY BOB---------------@@@")
    
    print(MAGENTA+"Cipher Text Received")
    
    print(GREEN+"[+]--- Decrypting Message at receiver's end...")
    time.sleep(1)
    p_text = aes.decrypt(c_text) #Call Decrypt Function
    print(BOLD+MAGENTA+"Recovered Plain Text:")
    print("Message:"+RESET+BLUE, p_text, "\n")
    
def secure_communication(message): 
    '''
    Facilitate Secure communication between Client and Server, via SSL/TLS using AES128 in CBC Mode.
    '''
    
    client = CLIENT_AES()    #Client Class Object
    cipher_text = _encrypt_message(client, message)    
    _send_message()
    
    server = SERVER_AES()    #Server Class Object
    plain_text = _decrypt_message(server, cipher_text)
    time.sleep(1)
    print(BOLD+GREEN+"---------------------------------------------------------------------------------")
    print("$$$$$$***********************MESSAGE COMMUNICATED SUCCESSFULLY***********************$$$$$$\n")
    return cipher_text


def main():
    print(BOLD+GREEN+"$$$$$$***********************SECURE SSL/TLS ESTABLISHED***********************$$$$$$")
    print("---------------------------------------------------------------------------------\n")
    
    #Original Message
    alice_message = [b'Harry Potter is a British American film series based on the eponymous novels by author' + 
    b" J. K. Rowling. The series is distributed by Warner Bros. and consists of eight fantasy films, beginning" + 
    b" with Harry Potter and the Philosophers Stone (2001) and culminating with Harry Potter and the Deathly" + 
    b" Hallows Part 2 (2011). A spin-off prequel series will consist of five films started with" + 
    b" Fantastic Beasts and Where to Find Them (2016), marking the beginning of the Wizarding World shared" + 
    b" media franchise."]
    
    #Establish Connection for communication b/w client and server
    encrypted_msg = secure_communication(alice_message[0])
    
    #Man In The Middle initiates Padding Oracle Attack 
    poa = PADDING_ORACLE_ATTACK()
    time.sleep(1)
    poa.man_inthe_middle_init(encrypted_msg)
    time.sleep(1)
    print(BOLD+RED+"\n\n$$$$$$********************---PADDING ORACLE ATTACK INITIATED---**********************$$$$$$\n")
    print("\n   --------------------------------# LET THE HACK BEGIN #-----------------------------------\n")
    time.sleep(1)
    hacked_msg = poa.padding_oracle_attack(encrypted_msg)
    print(BOLD+RED+"\n\n$$$$$$********************---PADDING ORACLE ATTACK SUCCESSFUL---*********************$$$$$$\n")
    print(MAGENTA+"\nCRACKED MESSAGE BY MAN IN THE MIDDLE:\n\n",RED, hacked_msg)
    
    return


if __name__ == '__main__':
    main()
    
    
        
        


# In[ ]:




