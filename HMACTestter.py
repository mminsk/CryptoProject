from Crypto.Hash import HMAC, SHA256
from Crypto import Random
s = Random.get_random_bytes(32)
print s

secret = s

from_user = "Bill"
header = "BeginChatSetup"

#FIRST TIME
#ENC KEY
h = HMAC.new(secret)
hash = SHA256.new()
hash.update(str(header + from_user + secret))
fresh_random =  hash.digest()
h.update(fresh_random)
label = "Encryption Key"
h.update(label)
h.digest_size=32
enc_key = h.hexdigest()
print enc_key

#MAC KEY
h = HMAC.new(secret)
hash = SHA256.new()
hash.update(str(header + from_user + secret))
fresh_random =  hash.digest()
h.update(fresh_random)
label = "MAC Key"
h.update(label)
h.digest_size=32
mac_key =  h.hexdigest()
print mac_key

#KEY FRESHNESS
#ENC KEY
h = HMAC.new(secret)
hash = SHA256.new()
hash.update(str(enc_key + mac_key))
fresh_random =  hash.digest()
h.update(fresh_random)
label = "Encryption Key"
h.update(label)
h.digest_size=32
enc_key =  h.hexdigest()
print enc_key


#MAC KEY
h = HMAC.new(secret)
hash = SHA256.new()
hash.update(str(enc_key + mac_key))
fresh_random =  hash.digest()
h.update(fresh_random)
label = "MAC Key"
h.update(label)
h.digest_size=32
mac_key =  h.hexdigest()
print mac_key
