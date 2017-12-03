import base64

import datetime
import os

from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

from RSA_pub_keys import RSAKeys


#generate key
#key = "0123456789abcdef0123456789abcdef"
keystring = "0123456789abcdef0123456789abcdef"
#key = os.urandom(AES.block_size)
#print "this is random key" + key

# BeginChatSetup|B|A|[Ta | PubEncKb(A|K) | Sigka(B|Ta|PubEnckB(A|K)]  )

# PubEncKB(A|K)
# RSA encryption using public key of user
user = "Bill"
for person in RSAKeys:
    if person["user_name"] == user:
        pubkey_file = person["RSA_public_key"]

        kfile = open(pubkey_file)
        keystr = kfile.read()
        kfile.close()

        pubkey = RSA.importKey(keystr)
        cipher = PKCS1_OAEP.new(pubkey)

        # plength = 214 - (len(msg) % 214)
        # msg += chr(plength) * plength
        msg = str("Bill") + str(keystring)

        encoded_msg = cipher.encrypt(msg)

        # B|Timstamp of manager|PubEncKB(A|K)
        time = datetime.datetime.now()
        print time
        msg_to_sign = str(user) + str(time) + encoded_msg

        # Generate signature
        kfile = open('private_keys/private_key_' + user + '.pem')
        keystr = kfile.read()
        kfile.close()
        key = RSA.importKey(keystr)

        signer = PKCS1_v1_5.new(key)
        digest = SHA256.new()
        digest.update(msg_to_sign)
        sign = signer.sign(digest)

        msg_to_send = "BeginChatSetup" + str(user) + str("Elon") + str(time) + encoded_msg + sign
        print len(encoded_msg)
        print len(sign)
        print msg_to_send

# BeginChatSetup|B|A|[Ta | PubEncKb(A|K) | Sigka(B|Ta|PubEnckB(A|K)]  )
print len(msg_to_send)
header = msg_to_send[0:14]
print header
from_user = msg_to_send[14:18]
print from_user
to_user = msg_to_send[18:22]
print to_user
timestamp = msg_to_send[22:48]
print timestamp

msg_to_decrypt=msg_to_send[48:304]
print msg_to_decrypt

sign_to_check = msg_to_send[304:]
print sign_to_check

kfile= open('private_keys/private_key_bill.pem')
kstr = kfile.read()
kfile.close()
key = RSA.importKey(kstr)
cipher = PKCS1_OAEP.new(key)
buffer = msg_to_decrypt
decrypted_msg =  cipher.decrypt(buffer)

shareSecret = decrypted_msg[-32:]
print shareSecret

kfile= open('public_keys/public_key_bill.pem')
pub_key = kfile.read()
kfile.close()
rsakey = RSA.importKey(pub_key)
signer = PKCS1_v1_5.new(rsakey)
digest = SHA256.new()
# Assumes the data is base64 encoded to begin with

data = str(from_user + timestamp + msg_to_decrypt)
print data

digest.update(data)
print signer.verify(digest, sign_to_check)



# list_of_users = self.manager.get_other_users()
#
# # generate key
# key = "abc"
# keystring="abc"
# #key = os.urandom(AES.block_size)
#
# for user in list_of_users:
#      #BeginChatSetup|B|A|[Ta | PubEncKb(A|K) | Sigka(B|Ta|PubEnckB(A|K)]  )
#
#      #PubEncKB(A|K)
#      # RSA encryption using public key of user
#      for person in RSAKeys:
#          if person["user_name"] == user:
#              pubkey_file = person["RSA_public_key"]
#
#              kfile = open(pubkey_file)
#              keystr = kfile.read()
#              kfile.close()
#
#              pubkey = RSA.importKey(keystr)
#              cipher = PKCS1_OAEP.new(pubkey)
#
#              # plength = 214 - (len(msg) % 214)
#              # msg += chr(plength) * plength
#              msg = str(self.manager.user_name)+ str(keystring)
#
#              encoded_msg = cipher.encrypt(msg)
#
#              # B|Timstamp of manager|PubEncKB(A|K)
#              time = datetime.datetime.now()
#              msg_to_sign = str(user) + str(time) + encoded_msg
#
#              # Generate signature
#              kfile = open('private_keys/private_key_'+user+'.pem')
#              keystr = kfile.read()
#              kfile.close()
#              key = RSA.importKey(keystr)
#
#              signer = PKCS1_v1_5.new(key)
#              digest = SHA256.new()
#              digest.update(msg_to_sign)
#              sign = signer.sign(digest)
#
#              msg_to_send = "BeginChatSetup" + str(user) + str(self.manager.user_name) + str(time) + encoded_msg + sign
#              print "before outgoing message"
#              print msg_to_send
#              self.process_outgoing_message(msg_to_send)




# for user in list_of_users:
#     for person in RSAKeys:
# #         if person["user_name"] == user:
# #             print person["RSA_public_key"]
# #             print datetime.datetime.now()
#