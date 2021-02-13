import math
import timeit
import random
import sympy
import warnings
from random import randint, seed
import sys
from ecpy.curves import Curve, Point
from Crypto.Hash import SHA3_256, SHA256, HMAC
import requests
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import random
import hashlib
import hmac
import binascii
import json
API_URL = 'http://cryptlygos.pythonanywhere.com'


stuID = 25334
stuID_B = 25389

# 13579
# 1

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

# Register Long Term Key

# ephemeral key class


class ephemeralKeys:
    def __init__(self, keyID, sa, Qa):
        super().__init__()
        self.keyID = keyID
        self.sa = sa
        self.Qa = Qa


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


def register(stuID, sl, QCli_long):

    signat = signMessage(stuID_B, sl)
    s, h = signat['s'], signat['h']
    mes = {'ID': stuID, 'H': h, 'S': s,
           'LKEY.X': QCli_long.x, 'LKEY.Y': QCli_long.y}
    response = requests.put('{}/{}'.format(API_URL, "RegLongRqst"), json=mes)
    print(response.json())

    code = int(input())

    mes = {'ID': stuID, 'CODE': code}
    response = requests.put('{}/{}'.format(API_URL, "RegLong"), json=mes)
    print(response.json())


def sendMessage(msg, stuID_A, stuID_B, EphemeralKeyList, sl):

    # ReceivedMessages.append(receivedMes(stuIDB, keyIDB, msg, Qbj_x, Qbj_y))
    keyIDA, keyIDB, Qbj_x, Qbj_y = getKey(stuID_A, stuID_B, sl)
    keyIDB = int(keyIDB)
    keyIDA = int(keyIDA)

    Qb = Point(Qbj_x, Qbj_y, E)
    T = EphemeralKeyList[0].sa * Qb

    Tx_str = str(T.x).encode()
    Ty_str = str(T.y).encode()
    temp_mes = b'NoNeedToRunAndHide'
    U = Tx_str + Ty_str + temp_mes
    K_enc = SHA3_256.new(U)
    K_enc = K_enc.digest()
    K_Mac = SHA3_256.new(K_enc)
    K_Mac = K_Mac.digest()
    # decrypt messages

    cipher = AES.new(K_enc, AES.MODE_CTR)
    h = HMAC.new(K_Mac, digestmod=SHA256)
    ctext = cipher.encrypt(msg)
    h.update(ctext)
    hmac = h.digest()
    ctext = cipher.nonce + ctext + hmac

    msg = ctext
    msg = int.from_bytes(msg, byteorder='big')
    # Send message to student B
    mes = {'ID_A': stuID_A, 'ID_B': stuID_B,
           'I': keyIDA, 'J': keyIDB, 'MSG': msg}
    response = requests.put('{}/{}'.format(API_URL, "SendMsg"), json=mes)
    print(response.json())


def resetKeys(stuID, sl):
    signat = signMessage(stuID, sl)
    s, h = signat['s'], signat['h']
    mes = {'ID': stuID, 'S': s, 'H': h}
    response = requests.get('{}/{}'.format(API_URL, "RstEKey"), json=mes)
    print(response.json())


# Check Status
def checkStatus(stuID, sl):

    signat = signMessage(stuID, sl)
    s, h = signat['s'], signat['h']
    mes = {'ID_A': stuID, 'H': h, 'S': s}
    response = requests.get('{}/{}'.format(API_URL, "Status"), json=mes)
    print("Status ", response.json())
    return response.json()


# Get your message
def getMSG(stuID, sl, ephemeral, Qbj_x, Qbj_y):
    signat = signMessage(stuID, sl)
    s, h = signat['s'], signat['h']
    mes = {'ID_A': stuID, 'S': s, 'H': h}
    response = requests.get('{}/{}'.format(API_URL, "ReqMsg_PH3"), json=mes)
    print(response.json())
    response = response.json()
    if(response == 'You dont have any new messages'):
        print("No message")
        return
    msg, Qbj_x, Qbj_y = response["MSG"], response["QBJ.X"], response["QBJ.Y"]

    #keyIDB = int(keyIDB)
    Qb = Point(Qbj_x, Qbj_y, E)
    T = ephemeral.sa * Qb

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


EphemeralKeyList = []


def addEphemeral(stuID, sl, EphemeralKeyList):
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
        print("Registered Key: \n ID: ", i, "\n sa: ",
              EphemeralKeyList[i].sa, "\n Qa: ", EphemeralKeyList[i].Qa)


def addEphemeraltoList(EphemeralKeyList, left):
    EphemeralKeyList.append(ephemeralKeys(0, 87361224168494230880529676870955552158232382392507852725827647556824013117533, (
        0xe545edad73b84930d330c03c95b9fdb7143cb72eb473f032f4921d20917359da, 0x60141d05de05605c37814d234dbda7321519dd5f2920e5a2a78c757574bf740)))
    EphemeralKeyList.append(ephemeralKeys(1, 83418328388366775893264700106930886509527639623050748332532661522406992118594, (
        0xaf2e2606bf5568d191ee799ef0d4169b9f21c82d5f5cb898c4f4a2a535e715e0, 0xbd28392193449a163cbfac1ad2c80e4604b069361867e4c8a70dedaf39675bc1)))
    EphemeralKeyList.append(ephemeralKeys(2, 33133530979547863382462479320470153440384021740026409174314069821596345167531, (
        0x220721cb954478a11097a6b07099fa99879621a62bcc88db967511b13e55f50d, 0xc33d9e6dd86029f80d4cc31c7cb257ae51a91b3ea55f42221c7db57a8833921e)))
    EphemeralKeyList.append(ephemeralKeys(3, 70469409825285710868268990932341807961209334179737671843190631795300692905918, (
        0xb0128050a07f17ef840ad4d2663bd06513912d461a757c00eeb0ddcf51de1e27, 0xcc645a42994ad50824869253e16ee0ce63f16de07d5f3c26499db631c5ffef64)))
    EphemeralKeyList.append(ephemeralKeys(4, 65730485090016313401267444694595109885925686569112249872152239228268957360570, (
        0x1e3c4456dfb5127726364315cb748add525835630408d2993623d3b5a1eab85f, 0xeb10d38f7307d37e8e84442bd5e6a0ca28704f9cd925966ad61d740d6fc85f98)))
    EphemeralKeyList.append(ephemeralKeys(5, 2444138758901467492025175108486087068088401308589866350316666256828553058968, (
        0x53a80d2bff9d8d847963b84749746c662b8818388ee53c687b73986915eeb483, 0xd3174b0d4d3c3b984972d5a9dc71e9776e225ea93306648be731e6387a9b3e15)))
    EphemeralKeyList.append(ephemeralKeys(6, 32087101055883959269566310661282249035184493169026678084989460496155255367773, (
        0xa54b447710f4ef5cd7c07d4c06854ef66b2e70e5202012c7efa88d28e9ba4854, 0x8f6d175935eb7408c8a65cb1d067460f53db0a66143492ef0d776f39078da61)))
    EphemeralKeyList.append(ephemeralKeys(7, 44194211646629294067054815491136956595813473164308462166124500519530128006337, (
        0x9d09b0524ca1180623a3888e2b66519929d663a81ce8eec1b0d243fd5d6460ea, 0x29307a84f5cdf0233654fa28b9177227ac5e2309efb84e8f9fabe7e4b0962422)))
    EphemeralKeyList.append(ephemeralKeys(8, 37853303658380308701890550321205626545891821852662232049919376286531077761242, (
        0x6efa577206a4e5fbf2f56943957bfa39a7f2e1591a8b8a85d9d42405f69697a4, 0xc8384be5db37c8dedd38d00a641e3e65d352e73550b3a3a317b3142e91a00b5c)))
    EphemeralKeyList.append(ephemeralKeys(9, 37188702247756062178745172683462579226836182483581778142438500471562808434627, (
        0xcaa86f3803dd5b898fee53f157efdf0a6718b9720441e959968cf92f5eac836d, 0x20dbe472a80853127eb0a0d3dc596e897bda3a62a8ad8a1256ac6b5ed0d144ae)))
    if('You have 10 keys remained. You need to send 0 keys' not in a):
        resetKeys(stuID, sl)
        for i in range(10):
            sa = EphemeralKeyList[i].sa
            Qa = sa * P
            ekey = Qa
            W = str(Qa.x) + str(Qa.y)
            signat = signMessage(W, sl)
            s, h = signat['s'], signat['h']
            mes = {'ID': stuID, 'KEYID': i, 'QAI.X': ekey.x,
                   'QAI.Y': ekey.y, 'Si': s, 'Hi': h}
            response = requests.put(
                '{}/{}'.format(API_URL, "SendKey"), json=mes)
            print(response.json())
            EphemeralKeyList.append(ephemeralKeys(i, sa, Qa))
            print("Registered Key: \n ID: ", i, "\n sa: ",
                  EphemeralKeyList[i].sa, "\n Qa: ", EphemeralKeyList[i].Qa)


def getKey(stuID_A, stuID_B, sl):
    signat = signMessage(stuID_B, sl)
    s, h = signat['s'], signat['h']
    # Get key of the Student B
    mes = {'ID_A': stuID_A, 'ID_B': stuID_B, 'S': s, 'H': h}
    response = requests.get('{}/{}'.format(API_URL, "ReqKey"), json=mes)
    response = response.json()
    print(response)
    keyIDA, keyIDB, Qbj_x, Qbj_y = response['i'], response[
        'j'], response['QBJ.x'], response['QBJ.y']
    return keyIDA, keyIDB, Qbj_x, Qbj_y


a = checkStatus(stuID, sl)

addEphemeraltoList(EphemeralKeyList, a)
keyIDA, keyIDB, Qbj_x, Qbj_y = getKey(stuID, stuID_B, sl)
getMSG(stuID, sl,  EphemeralKeyList[int(keyIDA)-1], Qbj_x, Qbj_y)
# resetKeys(stuID, sl)
# addEphemeral(stuID, sl, EphemeralKeyList)
'''
sendMessage(b"The world is full of lonely people afraid to make the first move. Tony Lip",
            stuID, stuID_B, EphemeralKeyList, sl)

sendMessage(b"I don't like sand. It's all coarse, and rough, and irritating. And it gets everywhere. Anakin Skywalker",
            stuID, stuID_B, EphemeralKeyList, sl)

sendMessage(b"Hate is baggage. Life's too short to be pissed o all the time. It's just not worth it. Danny Vinyard",
            stuID, stuID_B, EphemeralKeyList, sl)

sendMessage(b"Well, sir, it's this rug I have, it really tied the room together. The Dude",
            stuID, stuID_B, EphemeralKeyList, sl)

sendMessage(b"Love is like taking a dump, Butters. Sometimes it works itself out. But sometimes, you need to give it a nice hard slimy push. Eric Theodore Cartman",
            stuID, stuID_B, EphemeralKeyList, sl)
'''
'''
# Send message to student B
mes = {'ID_A': stuID, 'ID_B': stuID_B, 'I': i, 'J': j, 'MSG': msg}
response = requests.put('{}/{}'.format(API_URL, "SendMsg"), json=mes)
print(response.json())


# Get your message
mes = {'ID_A': stuID, 'S': s, 'H': h}
response = requests.get('{}/{}'.format(API_URL, "ReqMsg_PH3"), json=mes)
print(response.json())
if(response.ok):  # Decrypt message
    1

# Reset Ephemeral Keys
s, h = SignGen("18007".encode(), curve, sCli_long)
mes = {'ID': stuID, 'S': s, 'H': h}
print(mes)
response = requests.get('{}/{}'.format(API_URL, "RstEKey"), json=mes)
print(response.json())


# Reset Long Term Key
mes = {'ID': stuID}
response = requests.get('{}/{}'.format(API_URL, "RstLongRqst"), json=mes)
print(response.json())
code = int(input())

mes = {'ID': stuID, 'CODE': code}
response = requests.get('{}/{}'.format(API_URL, "RstLong"), json=mes)
print(response.json())
'''
