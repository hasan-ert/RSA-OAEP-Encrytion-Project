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

# Group Members
# Hasan Ertuğrul Çinar
# Ali Ceylan

stuID = 25334  # Hasan E. Çinar's ID


# HERE CREATE A LONG TERM KEY
E = Curve.get_curve('secp256k1')
n = E.order
p = E.field
P = E.generator

# private key
sl = 113235488862960744380139634917335050488728525474882888046082187325195659645673

# public key
Ql = sl*P
lkey = Ql
# Longterm public key: 73131960073630504879918912526880812563503981557950787838154440281260091807122 36977257115572914450952590895048905618666721768020825093363539721517244241433

# server's long term key
QSer_long = Point(0xc1bc6c9063b6985fe4b93be9b8f9d9149c353ae83c34a434ac91c85f61ddd1e9,
                  0x931bd623cf52ee6009ed3f50f6b4f92c564431306d284be7e97af8e443e69a8c, E)

# HERE GENERATE A EPHEMERAL KEY
sa = randint(1, n-1)
Qa = sa * P
ekey = Qa


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
    m = str(m).encode()
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
    Qb = Skey

    T = sa*Qb
    Tx_str = str(T.x).encode()
    Ty_str = str(T.y).encode()
    temp_mes = b'BeYourselfNoMatterWhatTheySay'
    message = Tx_str + Ty_str + temp_mes
    K = SHA3_256.new(message)
    K = K.digest()

    # Sign Message

    ax = str(Qa.x)
    ay = str(Qa.y)
    bx = str(Qb.x)
    by = str(Qb.y)
    signMes = ax+ay+bx+by
    signature = signMessage(signMes, sl)
    y1 = b's' + str(signature['s']).encode() + \
         b'h' + str(signature['h']).encode()

    # Encryption
    key = K
    cipher = AES.new(key, AES.MODE_CTR)
    enc = cipher.encrypt(y1)
    ctext = cipher.nonce[0:8] + enc
    ctext = int.from_bytes(ctext, byteorder='big')

    mes = {'ID': stuID, 'FINAL MESSAGE': ctext}
    response = requests.put('{}/{}'.format(API_URL, "STSStep4&5"), json=mes)
    if((response.ok) == False):
        raise Exception(response.json())
    ctext = response.json()
    print(ctext)

    # Decrypt
    ctext = ctext.to_bytes((ctext.bit_length()+7)//8, byteorder='big')
    W2 = bx+by+ax+ay
    cipher = AES.new(key, AES.MODE_CTR, nonce=ctext[0:8])
    dtext = cipher.decrypt(ctext[8:])

    sb = b''
    hb = b''
    a = str(dtext)
    print(dtext)
    for i in range(len(a)-1):
        if a[i] == 'h':
            sb = a[3:i]
            hb = a[i+1:len(a)-2]
    sb = int(sb)
    hb = int(hb)

    # verify
    isTrue = verifyMessage(W2, sb, hb)
    if isTrue:
        print("Verified!")
    else:
        print("Not verified!")
    # get a message from server for
    mes = {'ID': stuID}
    response = requests.get('{}/{}'.format(API_URL, "STSStep6"), json=mes)
    ctext = response.json()

    # Decrypt
    ctext = ctext.to_bytes(((ctext.bit_length()+7)//8), byteorder='big')
    cipher = AES.new(key, AES.MODE_CTR, nonce=ctext[0:8])
    dtext = cipher.decrypt(ctext[8:])
    print(dtext)

    # Get random number
    random_num = dtext[len(dtext)-9:]
    random_num = int.from_bytes(random_num, byteorder='big')

    # Add 1 to random to create the new message and encrypt it
    random_num += 1
    random_num = random_num.to_bytes(
        (random_num.bit_length()+7)//8, byteorder='big')
    dtext = dtext[:len(dtext)-9] + random_num
    print(dtext)

    # Encrypt the new message
    cipher = AES.new(key, AES.MODE_CTR)
    ct = cipher.nonce + cipher.encrypt(dtext)
    ct = int.from_bytes(ct, byteorder='big')

    # send the message and get response of the server
    mes = {'ID': stuID, 'ctext': ct}
    response = requests.put('{}/{}'.format(API_URL, "STSStep7&8"), json=mes)
    ctext = response.json()

    ctext = ctext.to_bytes(((ctext.bit_length()+7)//8), byteorder='big')
    cipher = AES.new(key, AES.MODE_CTR, nonce=ctext[0:8])
    # random_num = int.from_bytes(cipher.nonce, byteorder='big')
    dtext = cipher.decrypt(ctext[8:])
    print(dtext)

except Exception as e:
    print(e)
