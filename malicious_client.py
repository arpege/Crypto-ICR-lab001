#!/usr/bin/env python3

import binascii
import struct
import sys
import socket
import time

HOST, PORT = "localhost", 54321

def parse_answer(time, answer):
    if len (answer) == 35:
        if answer[0] >= 0x08 and answer[0] <= 0x0B:
            r_timestamp  = answer[1:9]
            r_ciphertext = answer[9:-10]
            r_tag        = answer[-10:]
            
            if answer[0] == 0x08:
                # print("[ANSWER IS: OK]")
                return 1
            elif answer[0] == 0x09:
                print("[ANSWER IS: WRONG TSP]")
                return 2
            elif answer[0] == 0x0A:
                # print("[ANSWER IS: PADDING ERROR]")
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
        sniffed_tram = b'\x00\x00\x00\x00\x00\x00\x00\x00\x0c\x8a\r=&\xf6z\xea\xea\xa1i\xb7Y\xfan\xb3E\xcfH<\xccwQ\xc7b\xed\xe3b3\xa2\x9c~\xda\xea\x06\x04\x97s\xd5\x92\xe8.\xe6\xd3c\x12\xb64\xa2J\xdd\xa3\xee\x9fBq\xd8\x15Hl\x11\xc8\xa2^-\xd6k\x05\xf3\xa7\t\xb6\x90\xdd`\xc8j\x80\xb6\x0eG\x08\x83{J#[\xb9\xdc\xdcc\xcf\xb0J\xac>\xa4W\xdf\xff\x87\xc8\x8f3\xf6\xa3\x0c'
        
        sniffed_header = sniffed_tram[:9]
        sniffed_ciphertext = sniffed_tram[9:-10]
        crop_sniffed_cipher = sniffed_ciphertext[16:]
        cipher0 = sniffed_ciphertext[:16]
        cipher1 = sniffed_ciphertext[16:32]
        
        
        progress = 1
        chosen_byte = 0
        byte_array = bytearray(b'\x00'*16);
        i2 = bytearray(b'\x00'*16);
        result = bytearray(b'\x00'*16);
        while progress < 17: 
            
            c1prime = open("/dev/urandom","rb").read(16-progress) + byte_array[-progress:]

            chosencipher = sniffed_header + c1prime + cipher1


            sock.sendall (chosencipher)
            
            
            # Receive data from the server and shut down
            response = parse_answer (0, sock.recv(35))
            
            if response == 1:
                
                print (progress)
                
                i2[16-progress] = chosen_byte ^ progress
                p2 = cipher0[16-progress] ^ i2[16-progress]
                pad = 1
                
                while pad <= progress:
                    next_pad = (progress+1) ^ i2[16-pad]
                    byte_array[16-pad] = next_pad
                    pad += 1
                
                progress += 1
                chosen_byte = 0
                
                print (i2)
                
                continue
            elif response > 1:
                print ("other error")
                break

            if chosen_byte+1 == 256:
                print("error, impossible to find next pad")
                break
            
            chosen_byte = (chosen_byte+1) % 256
            byte_array[16-progress] = chosen_byte

        
        
        i = 0
        while i < 16:
            result[i] = cipher0[i] ^ i2[i]
            i += 1
        
        print (result)
        
        
    finally:
        sock.close()
