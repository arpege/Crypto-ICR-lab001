#!/usr/bin/env python3

# The MIT License (MIT)
# Copyright (c) 2016 Joel Gugger <joel.gugger@master.hes-so.ch>
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

  
def encrypt_data_wrong_mac (timestamp, data):

    IV = b'\x00'*8 + timestamp

    # Padding operation
    to_pad = 16 - (len(data) % 16)
    plaintext = data.encode() + struct.pack('B', to_pad) * to_pad
    ciphertext = AES.new (client.KEY_E, AES.MODE_CBC, IV).encrypt (plaintext)
    tag = HMAC.new (client.KEY_A, data.encode(), SHA256).digest()[:10] # hash without the padding

    return b'\x00' + timestamp + ciphertext + tag



if __name__ == '__main__' :
  
  t = int(time.time())
  # print("\ntest for timestamp : " + str(t))
  print("Result expected : OK")
  client.main(t, 'toto')
  
  # print("\nre-test for timestamp : " + str(t))
  print("\nResult expected : WRONG TSP")
  client.main(t, 'toto')
  
  sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  
  try:
      # Connect to server and send data
      sock.connect((client.HOST, client.PORT))

      #print("\ntest for padding : ")
      #print("timestamp : " + str(int(t)+4))
      print("\nResult expected : PADDING ERROR")
      timestamp = struct.pack('>q', t+4)
      sock.sendall (encrypt_data_wrong_pad (timestamp, 'datadata'))

      client.parse_answer (t+4, sock.recv(35))
      
      #print("\ntest for mac : ")
      #print("timestamp : " + str(int(t)+5))
      print("\nResult expected : MAC ERROR")
      
      timestamp = struct.pack('>q', t+6)
      crypt = encrypt_data_wrong_mac(timestamp, 'data')
      sock.sendall (crypt)
      client.parse_answer (t+6, sock.recv(35))
      
  finally:
      sock.close()
  
  
  
  