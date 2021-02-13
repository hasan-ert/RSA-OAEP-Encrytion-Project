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
sl = 17038303632424682640790163221106780749952726053978479565773421509982984975572
Ql = sl*P

# server's long term key
QSer_long = Point(0xc1bc6c9063b6985fe4b93be9b8f9d9149c353ae83c34a434ac91c85f61ddd1e9,
                  0x931bd623cf52ee6009ed3f50f6b4f92c564431306d284be7e97af8e443e69a8c, curve)

# HERE GENERATE A EPHEMERAL KEY

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
lkey = Ql

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
        raise Exception(responce.json())
    res = response.json()

    # calculate T,K,U

    # Sign Message

    # Encyption

    # Send encrypted-signed keys and retrive server's signed keys
    mes = {'ID': stuID, 'FINAL MESSAGE': ctext}
    response = requests.put('{}/{}'.format(API_URL, "STSStep4&5"), json=mes)
    if((response.ok) == False):
        raise Exception(response.json())
    ctext = response.json()

    # Decrypt

    # verify

    # get a message from server for
    mes = {'ID': stuID}
    response = requests.get('{}/{}'.format(API_URL, "STSStep6"), json=mes)
    ctext = response.json()

    # Decrypt

    # Add 1 to random to create the new message and encrypt it

    # send the message and get response of the server
    mes = {'ID': stuID, 'ctext': ct}
    response = requests.put('{}/{}'.format(API_URL, "STSStep7&8"), json=mes)
    ctext = response.json()


except Exception as e:
    print(e)
