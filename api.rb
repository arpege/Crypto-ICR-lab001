#!/usr/bin/ruby -w

decipher = OpenSSL::Cipher::AES.new(128, :CBC)
decipher.decrypt
decipher.key = "the most secret!"
decipher.iv = "also very secret"

plain = decipher.update("thewrongpadding!") + decipher.final

