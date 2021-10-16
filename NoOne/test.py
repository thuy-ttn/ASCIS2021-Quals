from base64 import b64decode, b64encode
from Crypto.Cipher import AES 

def xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

username = 'thuyttn'
usernamebytes = username.encode('utf-8')
usernamelen = len(usernamebytes)

ori_role=1
ori_plainbytes = len(usernamebytes).to_bytes(2, "little") + usernamebytes + ori_role.to_bytes(1, "little")
print("ori_plainbytes: {}".format(ori_plainbytes))

new_role=0
new_plainbytes = len(usernamebytes).to_bytes(2, "little") + usernamebytes + new_role.to_bytes(1, "little")
print("new_plainbytes: {}".format(new_plainbytes))

ori_auth_encode = 'k4m6l09QOkYt016HjZj2mfJ6hFX7Z3jGVfE='
iv = b64decode(ori_auth_encode)[:16]
ori_auth = b64decode(ori_auth_encode)[16:]
print("ori_auth: {}".format(ori_auth))

new_auth = xor(ori_auth, xor(ori_plainbytes, new_plainbytes))
print("new_auth: {}".format(new_auth))
print(b64encode(iv + new_auth))