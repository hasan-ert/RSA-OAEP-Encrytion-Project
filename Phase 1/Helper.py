import math
import timeit
import random
import sympy
import warnings
from random import randint, seed
import sys
from ecpy.curves import Curve, Point
from Crypto.Hash import SHA3_256
import requests
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import random
import re
import json
from ecpy.keys import ECPublicKey, ECPrivateKey
import Crypto

E = Curve.get_curve('secp256k1')
n = E.order
p = E.field
P = E.generator

sl = randint(1, n-1)
print(sl)
Ql = sl*P
k = randint(1, n-2)
print(k)

private_key = ECPrivateKey(sl, E)
public_key = ECPublicKey(Ql)
print(public_key)
print(Ql)

k = 20967268688617224174982933461310353788514947376882738313418411876788905251145
R = k*P
r = pow(R.x, 1, n)
m = b'Hello World!'
r = r.to_bytes((r.bit_length()+7)//8, byteorder='big')
print(m+r)
mt = m+r
mt = int.from_bytes(mt, byteorder='big')
h = mt % n

s = pow(h*sl+k, 1, n)

print(h, "\n", s)


'''
import math
import timeit
import random
import sympy
import warnings
from random import randint, seed
import sys
from ecpy.curves import Curve, Point
from Crypto.Hash import SHA3_256
import requests
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import random
import re
import json

API_URL = 'http://cryptlygos.pythonanywhere.com'

stuID = 25334

# HERE CREATE A LONG TERM KEY
E = Curve.get_curve('secp256k1')
n = E.order
p = E.field
P = E.generator

# private key
sl = 113235488862960744380139634917335050488728525474882888046082187325195659645673
sa = sl
# public key
Ql = sl*P


# server's long term key
QSer_long = Point(0xc1bc6c9063b6985fe4b93be9b8f9d9149c353ae83c34a434ac91c85f61ddd1e9,
                  0x931bd623cf52ee6009ed3f50f6b4f92c564431306d284be7e97af8e443e69a8c, E)

# HERE GENERATE A EPHEMERAL KEY
Qa = Ql
lkey = Ql
ekey = Ql


def signMessage(m, sl):
    # Signature Generation
    k = randint(1, n-2)
    R = k*P
    r = pow(R.x, 1, n)
    m = str(m).encode()
    r = r.to_bytes((r.bit_length()+7)//8, byteorder='big')

    # Concatenate
    mt = m+r

    h = (SHA3_256.new(mt))
    h_ = h.digest()
    h = int.from_bytes(h_, byteorder='big')
    h = pow(h, 1, n)
    s = pow(h*sl+k, 1, n)
    # signature
    sig = {'s': s, 'h': h}
    return sig


def verifyMessage(m, s, h):
    # Verification
    V = (s*P) - (h*Ql)
    v = pow(V.x, 1, n)
    v = v.to_bytes((v.bit_length()+7)//8, byteorder='big')
    # Concatenate
    Z = m+v
    h_ = (SHA3_256.new(Z))
    h_ = h_.digest()
    h_ver = int.from_bytes(h_, byteorder='big')
    h_ver = pow(h_ver, 1, n)
    if h_ver != h:
        return True
    else:
        return False

# Registration


signat = signMessage(stuID, sl)
s, h = signat['s'], signat['h']

try:
    
    # REGISTRATION
    mes = {'ID': stuID, 'h': h, 's': s, 'LKEY.X': lkey.x, 'LKEY.Y': lkey.y}
    response = requests.put('{}/{}'.format(API_URL, "RegStep1"), json=mes)
    if((response.ok) == False):
        raise Exception(response.json())
    print(response.json())

    print("Enter verification code which is sent to you: ")
    code = int(input())

    mes = {'ID': stuID, 'CODE': code}
    response = requests.put('{}/{}'.format(API_URL, "RegStep3"), json=mes)
    if((response.ok) == False):
        raise Exception(response.json())
    print(response.json())
    
    # STS PROTOCOL

    mes = {'ID': stuID, 'EKEY.X': ekey.x, 'EKEY.Y': ekey.y}
    response = requests.put('{}/{}'.format(API_URL, "STSStep1&2"), json=mes)
    if((response.ok) == False):
        raise Exception(response.json())
    res = response.json()

    # calculate T,K,U
    Skey = Point(res['SKEY.X'], res['SKEY.Y'], E)
    T = sa*Skey
    Tx_str = str(T.x).encode()
    Ty_str = str(T.y).encode()
    temp_mes = b'BeYourselfNoMatterWhatTheySay'
    message = Tx_str+Ty_str+temp_mes
    K = (SHA3_256.new(message))
    K_ = K.digest()

    # Sign Message
    Qb = Skey
    ax = str(Qa.x).encode()
    ay = str(Qa.y).encode()
    bx = str(Qb.x).encode()
    by = str(Qb.y).encode()
    signMes = ax+ay+bx+by
    signature = signMessage(signMes, sl)
    y1 = b's'+str(signature['s']).encode()+b'h'+str(signature['h']).encode()
    # Encryption
    key = K_
    cipher = AES.new(key, AES.MODE_CTR)
    ctext = cipher.nonce + cipher.encrypt(y1)
    ctext = int.from_bytes(ctext, byteorder='big')

    mes = {'ID': stuID, 'FINAL MESSAGE': ctext}
    response = requests.put('{}/{}'.format(API_URL, "STSStep4&5"), json=mes)
    if((response.ok) == False):
        raise Exception(response.json())
    ctext = response.json()
    print(ctext)
    # Encyption
except Exception as e:
    print(e)

'''
