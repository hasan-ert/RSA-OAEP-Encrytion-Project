import math
import timeit
import random
import sympy
import warnings
from random import randint, seed
import sys
from ecpy.curves import Curve, Point
from Crypto.Hash import HMAC, SHA256, SHA3_256
import requests
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import random
import re
import json
import hmac
API_URL = 'http://cryptlygos.pythonanywhere.com'


# Hasan Ertuğrul Çianr
# Ali Ceylan

stuID = 25334  # Hasan E. Çinar

# create a long term key

E = Curve.get_curve('secp256k1')
n = E.order
p = E.field
P = E.generator

# private key
sl = 113235488862960744380139634917335050488728525474882888046082187325195659645673

# public key
Ql = sl*P
QCli_long = Ql

# server's long term key
QSer_long = Point(0xc1bc6c9063b6985fe4b93be9b8f9d9149c353ae83c34a434ac91c85f61ddd1e9,
                  0x931bd623cf52ee6009ed3f50f6b4f92c564431306d284be7e97af8e443e69a8c, E)


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

'''
# Register Long Term Key
mes = {'ID': stuID, 'H': h, 'S': s,
       'LKEY.X': QCli_long.x, 'LKEY.Y': QCli_long.y}
response = requests.put('{}/{}'.format(API_URL, "RegLongRqst"), json=mes)
print(response.json())
code = input()

mes = {'ID': stuID, 'CODE': code}
response = requests.put('{}/{}'.format(API_URL, "RegLong"), json=mes)
print(response.json())
'''

# delete old ephemeral keys from last run
mes = {'ID': stuID, 'S': s, 'H': h}
response = requests.get('{}/{}'.format(API_URL, "RstEKey"), json=mes)


class ephemeralKeys:
    def __init__(self, keyID, sa, Qa):
        super().__init__()
        self.keyID = keyID
        self.sa = sa
        self.Qa = Qa


EphemeralKeyList = []

for i in range(10):
    # Generate Ephemeral Keys
    sa = randint(1, n-2)
    Qa = sa * P
    ekey = Qa

    # Sign Ephemeral Keys
    W = str(Qa.x) + str(Qa.y)
    signat = signMessage(W, sl)
    s, h = signat['s'], signat['h']
    # send ephemeral key
    mes = {'ID': stuID, 'KEYID': i, 'QAI.X': ekey.x,
           'QAI.Y': ekey.y, 'Si': s, 'Hi': h}
    response = requests.put('{}/{}'.format(API_URL, "SendKey"), json=mes)
    print(response.json())
    EphemeralKeyList.append(ephemeralKeys(i, sa, Qa))
    print("Registered Key: \n ID: ", i, " \n Sa: ", EphemeralKeyList[i].sa)


# Receiving Messages

for i in range(5):

    signat = signMessage(stuID, sl)
    s, h = signat['s'], signat['h']

    mes = {'ID_A': stuID, 'S': s, 'H': h}
    response = requests.get('{}/{}'.format(API_URL, "ReqMsg"), json=mes)
    print()
    print(response.json())
    response = response.json()
    stuIDB, keyIDB, msg, Qbj_x, Qbj_y = response['IDB'], response[
        'KEYID'], response['MSG'], response['QBJ.X'], response['QBJ.Y']
    #ReceivedMessages.append(receivedMes(stuIDB, keyIDB, msg, Qbj_x, Qbj_y))

    keyIDB = int(keyIDB)
    Qb = Point(Qbj_x, Qbj_y, E)
    T = EphemeralKeyList[keyIDB].sa * Qb

    Tx_str = str(T.x).encode()
    Ty_str = str(T.y).encode()
    temp_mes = b'NoNeedToRunAndHide'
    U = Tx_str + Ty_str + temp_mes
    K_enc = SHA3_256.new(U)
    K_enc = K_enc.digest()

    K_Mac = SHA3_256.new(K_enc)
    K_Mac = K_Mac.digest()

    # decrypt messages
    msg = msg.to_bytes((msg.bit_length()+7)//8, byteorder='big')
    # 256 bit mac 8 bit nonce
    hmac = msg[-32:]
    msg = msg[: len(msg)-32]
    h = HMAC.new(K_Mac, digestmod=SHA256)
    h.update(msg[8:])
    hmac_ver = h.digest()
    if hmac == hmac_ver:
        cipher = AES.new(K_enc, AES.MODE_CTR, nonce=msg[:8])
        dtext = cipher.decrypt(msg[8:])
        print()
        print("dtext: ", str(dtext))
        h = str(dtext)
        # send decrypted messages to server
        mes = {'ID_A': stuID, 'DECMSG': h}
        response = requests.put('{}/{}'.format(API_URL, "Checker"), json=mes)


'''
# delete ephemeral keys
mes = {'ID': stuID, 'S': s, 'H': h}
response = requests.get('{}/{}'.format(API_URL, "RstEKey"), json=mes)

# DELETE LONG TERM KEY
# If you lost your long term key, you can reset it yourself with below code.

# First you need to send a request to delete it.
mes = {'ID': stuID}
response = requests.get('{}/{}'.format(API_URL, "RstLongRqst"), json=mes)

# Then server will send a verification code to your email.
# Send this code to server using below code
code = input()
mes = {'ID': stuID, 'CODE': code}
response = requests.get('{}/{}'.format(API_URL, "RstLong"), json=mes)

# Now your long term key is deleted. You can register again.
'''
