#!/usr/bin/env python3

# The MIT License (MIT)
# Copyright (c) 2016 Pascal Junod <pascal.junod@heig-vd.ch>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is furnished
# to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# Version 1.0 (09-02-2016)
#
# Networking code inspired from
# http://www.lampdev.org/programming/python/python-udp-server-python-implementation-tutorial.html

import binascii
import struct
import sys
import socket
import time
from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC

HOST, PORT = "localhost", 54321

def parse_answer(time, answer):
    if len (answer) == 35:
        if answer[0] >= 0x08 and answer[0] <= 0x0B:
            r_timestamp  = answer[1:9]
            r_ciphertext = answer[9:-10]
            r_tag        = answer[-10:]
            
            if answer[0] == 0x08:
                print("[ANSWER IS: OK]")
                return 1
            elif answer[0] == 0x09:
                print("[ANSWER IS: WRONG TSP]")
                return 2
            elif answer[0] == 0x0A:
                print("[ANSWER IS: PADDING ERROR]")
                return 0
            elif answer[0] == 0x0B:
                print("[ANSWER IS: MAC ERROR]")
                return 2

        else:
            print ("[ANSWER WITH INVALID CODE]")
            return 2
    else:
        print ("[ANSWER WITH INVALID LENGTH]")
        return 2


if __name__ == '__main__':
    
    
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect((HOST, PORT))
        
        
        # the intercepted message
        # b'\x00\x00\x00\x00\x00\x00\x00\x00\x0c\x8a\r=&\xf6z\xea\xea\xa1i\xb7Y\xfan\xb3E\xcfH<\xccwQ\xc7b\xed\xe3b3\xa2\x9c~\xda\xea\x06\x04\x97s\xd5\x92\xe8.\xe6\xd3c\x12\xb64\xa2J\xdd\xa3\xee\x9fBq\xd8\x15Hl\x11\xc8\xa2^-\xd6k\x05\xf3\xa7\t\xb6\x90\xdd`\xc8j\x80\xb6\x0eG\x08\x83{J#[\xb9\xdc\xdcc\xcf\xb0J\xac>\xa4W\xdf\xff\x87\xc8\x8f3\xf6\xa3\x0c'
        
        sniffed_tram = b'\x00\x00\x00\x00\x00\x00\x00\x00\x0c\x8a\r=&\xf6z\xea\xea\xa1i\xb7Y\xfan\xb3E\xcfH<\xccwQ\xc7b\xed\xe3b3\xa2\x9c~\xda\xea\x06\x04\x97s\xd5\x92\xe8.\xe6\xd3c\x12\xb64\xa2J\xdd\xa3\xee\x9fBq\xd8\x15Hl\x11\xc8\xa2^-\xd6k\x05\xf3\xa7\t\xb6\x90\xdd`\xc8j\x80\xb6\x0eG\x08\x83{J#[\xb9\xdc\xdcc\xcf\xb0J\xac>\xa4W\xdf\xff\x87\xc8\x8f3\xf6\xa3\x0c'
        
        sniffed_header = sniffed_tram[:9]
        sniffed_ciphertext = sniffed_tram[9:-10]
        crop_sniffed_cipher = sniffed_ciphertext[16:]
        
        progress = 1
        chosen_byte = 0
        byte_array = bytearray(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'); # 16 bit
        while progress < 17: 
            
            
            c1prime = open("/dev/urandom","rb").read(16-progress) + byte_array[-progress:]

            chosencipher = sniffed_header + c1prime + crop_sniffed_cipher


            sock.sendall (chosencipher)
            
            
            # Receive data from the server and shut down
            response = parse_answer (0, sock.recv(35))
            
            if response == 1:
                progress += 1
                chosen_byte = 0
                print (c1prime)
                continue
            elif response > 1:
                print ("other error")
                break

            chosen_byte = (chosen_byte+1) % 255
            byte_array[16-progress] = chosen_byte

            #print (chosen_byte)
            #print (byte_array)
            
            
#                my_int = struct.unpack('>H', b'\x00' + chosen_byte)[0]
#                next_byte = my_int+1
#                p = -progress+1
#                byte_array[p] = next_byte
#                chosen_byte = bin(next_byte)


        
        print (byte_array)
        
        i = 0
        while i < 16:
            i2 = struct.unpack('BBBBBBBBBBBBBBBB', byte_array)[i] ^ struct.unpack('BBBBBBBBBBBBBBBB', crop_sniffed_cipher[:16])[i]
            p2 = struct.unpack('BBBBBBBBBBBBBBBB', sniffed_ciphertext[:16])[i] ^ i2
            print ( chr(p2) )
            i += 1
        
        
        
        
    finally:
        sock.close()
