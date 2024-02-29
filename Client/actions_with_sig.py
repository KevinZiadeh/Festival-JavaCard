from smartcard.System import readers
from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.util import toHexString

from Crypto.PublicKey import RSA
from Crypto.PublicKey.pubkey import pubkey
from sys import byteorder
from Crypto.PublicKey.RSA import construct

CLA = 0xB0
READER_PUBKEY_MOD = 0x50
READER_PUBKEY_EXP = 0x51
CARD_PUBKEY_MOD = 0x60
CARD_PUBKEY_EXP = 0x61
P1,P2 = 0x00, 0x00
CONNECTION = None
Le = 0x00

def generateReaderKeys():
    privKey = RSA.generate(1024)
    with open("reader_privKey.pem", 'wb') as file:
        file.write(privKey.exportKey())
        
    pubkey = privKey.publickey()
    with open("reader_pubKey.pem", 'wb') as file:
        file.write(pubKey.exportKey())
        
def retrieveReaderKeys():
    with open("reader_privKey.pem", 'wb') as file:
        reader_privKey = RSA.importKey(file.read())
        
    with open("reader_pubKey.pem", 'wb') as file: 
        reader_pubKey = RSA.importKey(file.read())
        
    return (reader_privKey, reader_pubKey)

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
    response = int.from_bytes(response, "big")
    return response, hex(sw1), hex(sw2)

def getCardKeyExp(connection):
    Lc = 0
    response, sw1, sw2 = connection.transmit([CLA, CARD_PUBKEY_EXP, P1, P2, Lc])
    response = int.from_bytes(response, "big")
    return response, hex(sw1), hex(sw2)

def constructCardKey(mod, exp):
    card_pubKey = construct(mod, exp)
    return card_pubKey

def saveCardKey(pubKey):
    with open("card_pubKey.pem",'wb') as file:
        file.write(pubKey.exportKey())

def main():
    generateReaderKeys()
    
if __name__ == '__main__':
    main()