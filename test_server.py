#!/usr/bin/env python3

# The MIT License (MIT)
# Copyright (c) 2016 Joel Gugger <joel.gugger@master.hes-so.ch>
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
# Version 1.0 (24-03-2016)
#
# Write a test suite in the programming language of your choice allowing to check 
# that both the client and the server security functionalities behave as expected, 
# including in case of error.
# 
# This is the test suite for the server side

import client
import time

import binascii
import struct
import sys
import socket


from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC


def encrypt_data_wrong_pad (timestamp, data):

    IV = b'\x00'*8 + timestamp

    # Padding operation
    to_pad =  16 - (len(data) % 16) 
    plaintext = data.encode() + struct.pack('B', to_pad) * to_pad
    plaintext =  plaintext[:len(data)+1] + b'\x00' + plaintext[len(data):-2]
    ciphertext = AES.new (client.KEY_E, AES.MODE_CBC, IV).encrypt (plaintext)
    tag = HMAC.new (client.KEY_A, plaintext, SHA256).digest()[:10]

    return b'\x00' + timestamp + ciphertext + tag


if __name__ == '__main__' :
  
  t = int(time.time())
  print("\ntest for timestamp : " + str(t))
  print("Result expected : OK")
  
  client.main(t, 'toto')
  
  print("\nre-test for timestamp : " + str(t))
  print("Result expected : WRONG TSP")
  
  client.main(t, 'toto')
  
  
  
  sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  
  try:
      # Connect to server and send data
      sock.connect((client.HOST, client.PORT))

      print("\ntest for padding : ")
      print("timestamp : " + str(int(t)+4))
      print("Result expected : PAD ERROR")
      timestamp = struct.pack('>q', t+4)
      sock.sendall (encrypt_data_wrong_pad (timestamp, 'datadata'))

      # Receive data from the server and shut down
      client.parse_answer (t+4, sock.recv(35))
      
      print("\ntest for mac : ")
      print("timestamp : " + str(int(t)+5))
      print("Result expected : MAC ERROR")
      
      timestamp = struct.pack('>q', t+5)
      crypt = client.encrypt_data(timestamp, 'data') + b'\x00'
      sock.sendall (crypt)
      client.parse_answer (t+5, sock.recv(35))
      
  finally:
      sock.close()
  
  
  
  