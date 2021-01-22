#!/usr/bin/python
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import re
import itertools
import collections 
import os
import urllib2
import sys



def ascii_to_bytelist(s):
    bl=[]
    for c in s:
        bl.append(ord(c))
    return bl

def hexstring_to_bytelist(s):
    bl=[]
    for c in re.findall(r'.{1,2}',s,re.DOTALL):
        bl.append(int(c,16))
    return bl

def bytelist_to_hexstring(bl):
    hs=''
    for b in bl:
        t=hex(b).split('0x')[1]
        if len(t)==1: 
            t='0'+t # prepend a leading zero if requred
    	hs+=t
    return hs

def bytelist_to_ascii(bl):
    s=''
    for c in bl:
        s+=chr(c)
    return s

def ascii_to_hexstring(a):
    return bytelist_to_hexstring(ascii_to_bytelist(a))

def hexstring_to_ascii(h):
    return bytelist_to_ascii(hexstring_to_bytelist(h))

def bytelist_xor(a,b):
    bl=[]
    if a>b:
        t=zip(a[:len(b)],b)
    else:
        t=zip(a,b[:len(a)])
    for (x,y) in t:
        bl.append(x^y)
    return bl

def bytelist_to_ascii_readable(bl):
    s=''
    for c in bl:
        if (c>64 and c<91) or (c>96 and c<123):
            s+=chr(c) 
        else:
            s+='?'
    return s

def bytelist_to_padblocks(bl):
    BLOCKSIZE=16
    blocks=[]
    n=len(bl)/BLOCKSIZE
    pad=BLOCKSIZE-len(bl)%BLOCKSIZE
    for i in range(pad):
        bl.append(pad)
    for i in range(n+1):
        blocks.append(bl[BLOCKSIZE*i:BLOCKSIZE*i+BLOCKSIZE])
    return blocks

def padblocks_to_bytelist(blocks):
    bl=[]
    for b in blocks[0:-1]:
        bl+=b
    pad=blocks[-1][-1]
    bl += blocks[-1][0:-pad]
    return bl

def bytelist_to_blocks(bl):
    BLOCKSIZE=16
    #assume we are the correct length
    assert(len(bl)%16==0)
    blocks=[]
    n=len(bl)/BLOCKSIZE
    for i in range(n):
        blocks.append(bl[BLOCKSIZE*i:BLOCKSIZE*i+BLOCKSIZE])
    return blocks
    
def blocks_to_bytelist(blocks):
    bl=[]
    for b in blocks:
        bl+=b
    return bl

def increment_counter(bl):
    ctr=bl[0]
    for b in bl[1:]:
        ctr=ctr*256+b
    ctr=ctr+1
    output=[]
    while ctr>0:
        output.insert(0,ctr%256)
        ctr=ctr/256
    while len(output)<16:
        output.insert(0,0)

    return output


def aes_encrypt_cbc(k,i,m):
    key=bytelist_to_ascii(hexstring_to_bytelist(k))
    iv=hexstring_to_bytelist(i)
    
    cipher=AES.new(key)
    output_blocks=[]
    bl=ascii_to_bytelist(m)
    blocks=bytelist_to_padblocks(bl)
    for b in blocks:
        mi=bytelist_to_ascii(bytelist_xor(iv,b))
        ci=cipher.encrypt(mi)
        iv=ascii_to_bytelist(ci) # use as iv for next interation
        output_blocks.append(iv)
    
    bl=blocks_to_bytelist(output_blocks)
    ciphertext=bytelist_to_hexstring(bl)
    return ciphertext

def aes_decrypt_cbc(k,c):
    key=bytelist_to_ascii(hexstring_to_bytelist(k))
    # iv=hexstring_to_bytelist(i)
    bl=hexstring_to_bytelist(c)
    blocks=bytelist_to_blocks(bl)
    output_blocks=[]

    cipher=AES.new(key)
    iv=blocks[0]
    for b in blocks[1:]:
        ci=bytelist_to_ascii(b)
        output_blocks.append(bytelist_xor(ascii_to_bytelist(cipher.decrypt(ci)),iv))
        iv=b
    bl=padblocks_to_bytelist(output_blocks)
    plaintext=bytelist_to_ascii(bl)
    return plaintext

def aes_encrypt_ctr(k,i,m):
    key=bytelist_to_ascii(hexstring_to_bytelist(k))
    iv=hexstring_to_bytelist(i)
    cipher=AES.new(key)
    
    msg=ascii_to_bytelist(m)
    rounds=len(msg)/16+1
    output_block=[]
    for i in range(rounds):
        ivs=bytelist_to_ascii(iv)
        out=ascii_to_bytelist(cipher.encrypt(ivs))
        output_block.append(bytelist_xor(out,msg[16*i:16*i+16]))
        iv=increment_counter(iv)
    ciphertext = bytelist_to_hexstring(blocks_to_bytelist(output_block))
    return ciphertext

def aes_decrypt_ctr(k,ct):
    key=bytelist_to_ascii(hexstring_to_bytelist(k))
    #iv=hexstring_to_bytelist(i)
    cipher=AES.new(key)
    
    c=hexstring_to_bytelist(ct)
    iv=c[0:16]
    c=c[16:]
    rounds=len(c)/16+1
    output_block=[]
    for i in range(rounds):
        ivs=bytelist_to_ascii(iv)
        out=ascii_to_bytelist(cipher.encrypt(ivs))
        output_block.append(bytelist_xor(out,c[16*i:16*i+16]))
        iv=increment_counter(iv)
    plaintext = bytelist_to_ascii(blocks_to_bytelist(output_block))
    return plaintext


def bytes_from_file(filename, chunksize=1024):
    blocks=[]
    block=[]
    with open(filename, "rb") as f:
        while True:
            chunk = f.read(chunksize)
            if chunk:
                for b in chunk:
                    block.append[b]
            else:
                break
        # return chunk

def bytes_from_file(filename, chunksize=1024):
    blocks=[]
    f=open(filename, "rb")
    while True:
        chunk = f.read(chunksize)
        if chunk=="": 
            break
        blocks.append(chunk)
    return blocks


def chainedhash(f):
    video=bytes_from_file(f,1024)
    num=len(video)
    #test=[["a","b"],["a","c"],["a","d"]]
    for i in range(num-1,0,-1):
        h = SHA256.new()
        h.update(video[i])
        if i !=0:
            bhash=h.digest()
            #print ascii_to_hexstring(video[i-1])
            #print ascii_to_hexstring(bhash)
            video[i-1]=video[i-1] + bhash
            #print ascii_to_hexstring(video[i-1])
    h = SHA256.new()
    h.update(video[0])
    # assert(h.hexdigest()=='03c08f4ee0b576fe319338139c045c89c3e8e9409633bea29442e21425006ea8')
    return h.hexdigest()


TARGET = 'http://crypto-class.appspot.com/po?er='
#--------------------------------------------------------------
# padding oracle
#--------------------------------------------------------------
#class PaddingOracle(object):
#def query(self, q):
def query(q):
    target = TARGET + urllib2.quote(q)    # Create query URL
    req = urllib2.Request(target)         # Send HTTP request to server
    try:
        f = urllib2.urlopen(req)          # Wait for response
    except urllib2.HTTPError, e:          
        # print "We got: %d" % e.code       # Print response code
        if e.code == 404:
            return True # good padding
        return False # bad padding




string="f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4"

def main():
    blocks=[]
    string_bytes=hexstring_to_bytelist(string)
    while string_bytes:
        blocks.append(string_bytes[:16])
        string_bytes=string_bytes[16:]
    message=[]
    for attack in range(len(blocks)-1): 
        padh=[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
        zh=[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
        zt=[]
        plain=[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
        for byte in range(1,17):
            #for g in range(0,256):
            for g in range(2,256): # we never guess a byte is "00" or "01" this helps us decrypt the last block, which has a correct pad already
                pad=[]
                pad.extend(padh)
                for i in range(byte):
                    pad.extend([byte])
                iv=blocks[attack]
                g_bytelist=[]
                g_bytelist.extend(zh)
                g_bytelist.extend([g])
                g_bytelist.extend(zt)
                #print "g",g_bytelist
                #print "pad",pad
                g_pad=bytelist_xor(g_bytelist,pad)
                iv=bytelist_xor(iv,bytelist_xor(g_pad,plain))
                s=bytelist_to_hexstring(iv)
                s=s+bytelist_to_hexstring(blocks[attack+1])
                #print s
                if query(s):
                    plain[16-byte]=g
                    print "discovered: ", plain
                    break
            zh=zh[:-1]
            zt.extend([0])
            padh=padh[:-1]
        message.extend(plain)
        print message
        print bytelist_to_ascii(message)



if __name__ == "__main__":
    main()

