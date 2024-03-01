import sys

from smartcard.System import readers
from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.util import toHexString

from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.PublicKey.RSA import construct
from Crypto.Signature import pkcs1_15


CLA = 0xB0
GET_BALANCE = 0x10;
CREDIT = 0x20;
DEBIT = 0x30;
READER_PUBKEY_MOD = 0x50
READER_PUBKEY_EXP = 0x51
CARD_PUBKEY_MOD = 0x60
CARD_PUBKEY_EXP = 0x61
SEND_SIGNED_MSG = 0x70
RECEIVE_SIGNED_MSG = 0x80
P1,P2 = 0x00, 0x00
CONNECTION = None
Le = 0x00


# def getBalance(connection):
#     Lc = 0
#     response, sw1, sw2 = connection.transmit([CLA, GET_BALANCE, P1, P2, Lc])
#     return response, hex(sw1), hex(sw2)
#
# def credit(connection, signedMessage):
#     Lc = len(signedMessage)
#     data, sw1, sw2 = connection.transmit([CLA, CREDIT, P1, P2, Lc] + list(signedMessage))
#     return data, hex(sw1), hex(sw2)
#
# def debit(connection, signedMessage):
#     Lc = len(signedMessage)
#     data, sw1, sw2 = connection.transmit([CLA, DEBIT, P1, P2, Lc] + list(signedMessage))
#     return data, hex(sw1), hex(sw2)

def generateReaderKeys():
    privKey = RSA.generate(1024)
    with open('reader_privKey.pem', 'wb') as file:
        file.write(privKey.exportKey())
        
    pubkey = privKey.publickey()
    with open('reader_pubKey.pem', 'wb') as file:
        file.write(pubKey.exportKey())
        
def retrieveReaderKeys():
    with open('reader_privKey.pem', 'wb') as file:
        reader_privKey = RSA.importKey(file.read())
        
    with open('reader_pubKey.pem', 'wb') as file: 
        reader_pubKey = RSA.importKey(file.read())
        
    pubKeyMod = reader_pubKey.n
    pubkeyExp = reader_pubKey.e
        
    return reader_privKey, reader_pubKey, pubKeyMod, pubkeyExp

def sendPubKeyMod(connection,mod):
    pubKeyMod = list(mod.to_bytes(128,byteorder='big'))
    Lc = len(pubKeyMod)
    data, sw1, sw2 = connection.transmit([CLA, READER_PUBKEY_MOD, P1, P2, Lc] + pubKeyMod)
    return data, hex(sw1), hex(sw2)

def sendPubKeyExp(connection,exp):
    pubKeyExp = list(mod.to_bytes(4,byteorder='big'))
    Lc = len(pubKeyExp)
    data, sw1, sw2 = connection.transmit([CLA, READER_PUBKEY_EXP, P1, P2, Lc] + pubKeyExp)
    return data, hex(sw1), hex(sw2)

def getCardKeyMod(connection):
    Lc = 0
    response, sw1, sw2 = connection.transmit([CLA, CARD_PUBKEY_MOD, P1, P2, Lc])
    response = int.from_bytes(response, 'big')
    return response, hex(sw1), hex(sw2)

def getCardKeyExp(connection):
    Lc = 0
    response, sw1, sw2 = connection.transmit([CLA, CARD_PUBKEY_EXP, P1, P2, Lc])
    response = int.from_bytes(response, 'big')
    return response, hex(sw1), hex(sw2)

def constructCardKey(mod, exp):
    card_pubKey = construct(mod, exp)
    return card_pubKey

def saveCardKey(pubKey):
    with open('card_pubKey.pem','wb') as file:
        file.write(pubKey.exportKey())
        
def signMessage(message_list):
    reader_privKey = RSA.importKey(open('reader_privKey.pem').read())
    message = bytes(message_list)
    hash = SHA256.new(message)
    signature = pkcs1_15.new(reader_privKey).sign(hash)
    return message + signature

def sendSigned(connection, signedMsg):
    Lc = len(signedMsg)
    data, sw1, sw2 = connection.transmit([CLA, SEND_SIGNED_MSG, P1, P2, Lc] + list(signedMsg))
    return data, hex(sw1), hex(sw2)

def receiveSigned(connection, signedMsg):
    Lc = len(signedMsg)
    response, sw1, sw2 = connection.transmit([CLA, RECEIVE_SIGNED_MSG, P1, P2, Lc] + signedMsg)
    return response, hex(sw1), hex(sw2)

def verifyMessage(message_list, signature):
    card_pubKey = RSA.importKey(open('card_pubKey.pem').read())
    message = bytes(message_list)
    hash = SHA256.new(message)
    signature = bytes(signature)
    try:
        pkcs1_15.new(card_pubKey).verify(hash, signature)
        return True
    except (ValueError, TypeError):
        return False
    
    
def main():
    r = readers()
    connection = r[0].createConnection() 
    connection.connect()
    
    generateReaderKeys()
    readerPrivKey, readerPubKey, readerKeyMod, readerKeyExp = retrieveReaderKeys()
    
    data, sw1, sw2 = sendPubKeyMod(connection, readerKeyMod)
    data, sw1, sw2 = sendPubKeyExp(connection, readerKeyExp) 
    
    
if __name__ == '__main__':
    main()