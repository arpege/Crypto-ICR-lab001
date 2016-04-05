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

KEY_A = binascii.a2b_hex ("f7400e4ab887eaf4a4dcd56ae47e0c8c0bf5d19489076ba163e106f4bde56e66")
KEY_E = binascii.a2b_hex ("6168b12773512824fc4166cc1cb41b4fad7edd63ff5bfd90302c22dfd3cb3db0")

def parse_answer(time, answer):
    if len (answer) == 35:
        if answer[0] >= 0x08 and answer[0] <= 0x0B:
            r_timestamp  = answer[1:9]
            r_ciphertext = answer[9:-10]
            r_tag        = answer[-10:]

            # Checking that the timestamp is acceptable, at least with
            # respect from our query
            t = struct.unpack('>q', r_timestamp)
            if t[0] > int(time) : # sys.argv[1]
                IV = b'\x00' * 8 + r_timestamp
                r_cleartext = AES.new (KEY_E, AES.MODE_CBC, IV).decrypt (r_ciphertext)
                if (HMAC.new(KEY_A, r_cleartext, SHA256).digest()[:10] != r_tag):
                    print ("[ANSWER WITH WRONG MAC]")
                else:
                    if answer[0] == 0x08:
                        print("[ANSWER IS: OK]")
                    elif answer[0] == 0x09:
                        print("[ANSWER IS: WRONG TSP]")
                    elif answer[0] == 0x0A:
                        print("[ANSWER IS: PADDING ERROR]")
                    elif answer[0] == 0x0B:
                        print("[ANSWER IS: MAC ERROR]")
            else:
                print ("[ANSWER WITH INVALID TIMESTAMP][TIMESTAMP = %s]" % t[0])
        else:
            print ("[ANSWER WITH INVALID CODE]")
    else:
        print ("[ANSWER WITH INVALID LENGTH]")

def encrypt_data (timestamp, data):

    IV = b'\x00'*8 + timestamp

    # Padding operation
    to_pad = 16 - (len(data) % 16)
    plaintext = data.encode() + struct.pack('B', to_pad) * to_pad
    ciphertext = AES.new (KEY_E, AES.MODE_CBC, IV).encrypt (plaintext)
    tag = HMAC.new (KEY_A, plaintext, SHA256).digest()[:10]

    return b'\x00' + timestamp + ciphertext + tag

def main (t, m):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    timestamp = struct.pack('>q', int(t))
    # timestamp = time.time() + 10
    data = m

    try:
        # Connect to server and send data
        sock.connect((HOST, PORT))
        # sock.sendall (encrypt_data (struct.pack('>q', int(timestamp)), data))
        sock.sendall (encrypt_data (timestamp, data))

        # Receive data from the server and shut down
        parse_answer (t, sock.recv(35))
    finally:
        sock.close()
  
if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
