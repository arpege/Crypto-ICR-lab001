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

# Version 1.0 (09-02-2016)

# Networking code inspired from
# http://www.lampdev.org/programming/python/python-udp-server-python-implementation-tutorial.html

import threading
import socketserver
import binascii
import struct
from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC

HOST, PORT = "localhost", 54321

KEY_A = binascii.a2b_hex ("f7400e4ab887eaf4a4dcd56ae47e0c8c0bf5d19489076ba163e106f4bde56e66")
KEY_E = binascii.a2b_hex ("6168b12773512824fc4166cc1cb41b4fad7edd63ff5bfd90302c22dfd3cb3db0")

# This value represents the last accepted timestamp
TIMESTAMP = -1
timestamp_mutex = threading.Lock ()

def new_timestamp ():
    global TIMESTAMP
    timestamp_mutex.acquire()
    TIMESTAMP += 1
    tsp = TIMESTAMP
    timestamp_mutex.release()

    return tsp

def set_timestamp (tsp):
    global TIMESTAMP
    # Acquiring the timestamp
    timestamp_mutex.acquire()
    if tsp > TIMESTAMP:
        TIMESTAMP = tsp
    timestamp_mutex.release()

def prepare_OK_message ():
    t = struct.pack('>q', new_timestamp())
    cleartext = b'\x00' * 16
    IV = b'\x00' * 8 + t

    ciphertext = AES.new (KEY_E, AES.MODE_CBC, IV).encrypt (cleartext)
    tag = HMAC.new (KEY_A, cleartext, SHA256).digest()[:10]
    print ("[OK][LAST USED TIMESTAMP: %s]" % str(TIMESTAMP))

    return b'\x08' + t + ciphertext + tag

def prepare_error_message (error_type):
    if error_type == "MAC" or error_type == "PAD" or error_type == "TSP":

        t = struct.pack('>q', new_timestamp())
        cleartext = b'\x00' * 16
        IV = b'\x00' * 8 + t

        ciphertext = AES.new (KEY_E, AES.MODE_CBC, IV).encrypt (cleartext)
        tag = HMAC.new (KEY_A, cleartext, SHA256).digest()[:10]

        if error_type == "MAC":
            print ("[MAC ERROR][LAST USED TIMESTAMP: %s]" % str(TIMESTAMP))
            return b'\x0B' + t + ciphertext + tag
        elif error_type == "PAD":
            print ("[PAD ERROR][LAST USED TIMESTAMP: %s]" % str(TIMESTAMP))
            return b'\x0A' + t + ciphertext + tag
        elif error_type == "TSP":
            print ("[TSP ERROR][LAST USED TIMESTAMP: %s]" % str(TIMESTAMP))
            return b'\x09' + t + ciphertext + tag

def decrypt_check_data (data):
    global TIMESTAMP

    # First, we check that the data length looks like to be correct
    # 0x00 + TTTTTTTT + I + MMMMMMMMMM = 20 bytes
    if (len(data) - 19) % 16 != 0:
        return (None, None)
    else:
        ## Data parsing

        # Checking that first byte is 0x00
        if data[0] != 0:
            return (None, None)
        r_timestamp  = data[1:9]
        r_ciphertext = data[9:-10]
        r_tag        = data[-10:]

        # Checking that the timestamp is acceptable
        t = struct.unpack('>q', r_timestamp)
        if (t[0] > TIMESTAMP):
            # We accept and update it
            print ("[ACCEPTED TIMESTAMP = %s]" % str(t[0]))
            set_timestamp (t[0])
        else:
            return (None, prepare_error_message("TSP"))

        IV = b'\x00' * 8 + r_timestamp
        r_cleartext = AES.new (KEY_E, AES.MODE_CBC, IV).decrypt (r_ciphertext)
        
        # Checking authentication tag
        if (HMAC.new(KEY_A, r_cleartext, SHA256).digest()[:10] != r_tag):
            # INVALID MAC
            return (None, prepare_error_message ("MAC"))
        else:
            # Checking padding
            count = r_cleartext[-1]
            if count == 0 or count > 16:
                return (None, prepare_error_message("PAD"))
            else:
                for i in range (1, count+1):
                    if r_cleartext[-i] != count:
                        return (None, prepare_error_message("PAD"))
            return (r_cleartext[:-count], prepare_OK_message())
           

class ThreadedUDPRequestHandler (socketserver.BaseRequestHandler):

    def handle (self):

        received_data  = self.request[0].strip ()
        port           = self.client_address[1]
        socket         = self.request[1]
        client_address = (self.client_address[0])
        current_thread = threading.current_thread()
        print ("[SERVER][%s][CONNECT from %s %s]" % (current_thread.name,
                                                          client_address,
                                                          port))
        print ("[ENCRYPTED DATA] %s" % received_data)
        (clean_data, msg) = decrypt_check_data (received_data)
        if clean_data is not None:
            print ("[DECRYPTED DATA] %s" % clean_data)
        # We send back the answer
        socket.sendto(msg, self.client_address)

class ThreadedUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    pass

if __name__ == "__main__":
    server = ThreadedUDPServer((HOST, PORT),
		ThreadedUDPRequestHandler)
    ip, port = server.server_address
    server.serve_forever()
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    server.shutdown()
