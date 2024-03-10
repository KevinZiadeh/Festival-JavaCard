import sys

from instructions import print_card_info, get_balance, transfer_credit, reimburse_credit, validate_pin, SELECT, AID
from helpers import wait_for_card, wait_for_card_removed


from smartcard.System import readers
from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.util import toHexString

from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
from Crypto.PublicKey.RSA import construct
from Crypto.Signature import pkcs1_15


CLA = 0xB0
GET_BALANCE = 0x10
CREDIT = 0x20
DEBIT = 0x30
GENERATE_CARD_KEYS = 0x40
READER_PUBKEY_MOD = 0x50
READER_PUBKEY_EXP = 0x51
READER_PUBKEY = 0x52
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

def constructPubKey(connection,msg_hexlist):
    Lc = len(message_hexlist)
    message_hexlist = str.encode(message_hexlist)
    data, sw1, sw2 = connection.transmit([CLA,READER_PUBKEY,P1,P2,Lc]+list(message_hexlist))
    return data,hex(sw1),hex(sw2)

def getCardKey(connection):
    Lc = 0
    data, sw1, sw2 = connection.transmit([CLA,GENERATE_CARD_KEYS,P1,P2,Lc])
    return data,hex(sw1),hex(sw2)


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
    n = mod
    e = exp
    card_pubKey = construct((n, e))
    print("Reader side, Car Pubkey" + str(card_pubKey))
    return card_pubKey

def saveCardKey(pubKey):
    with open('card_pubKey.pem','wb') as file:
        file.write(pubKey.exportKey())
        
def signMessage(message_list):
    reader_privKey = RSA.importKey(open('reader_privKey.pem').read())
    message = bytes(message_list)
    hash = SHA.new(message)
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
    hash = SHA.new(message)
    signature = bytes(signature)
    try:
        pkcs1_15.new(card_pubKey).verify(hash, signature)
        return True
    except (ValueError, TypeError):
        return False
    
    
def main():
    connection = wait_for_card()
    print("Card Detected...")

    #Selection AID
    _, sw1, sw2 = connection.transmit(SELECT + AID)
    if sw1 != 0x90 and sw2 != 0x00:
        raise Exception("There was an error with your card. Please go to the nearest branch for assistance")
        
    card_name = ""
    card_number = ""
    card_name, card_number = print_card_info(connection, card_name, card_number)
    if not card_name or not card_number:
        raise Exception("There was an error with your card. Please go to the nearest branch for assistance")
                        
    valid = validate_pin(connection)
    
    data, sw1, sw2 = getCardKey(connection)
    

    

    data, sw1, sw2 = connection.transmit([CLA, 0x60, 0x00, 0x00, 0x00])
    
    card_pub_mod_len = (data[0] << 8) + data[1]
    card_pub_mod = data[2:card_pub_mod_len]
    card_pub_exp_len =  (data[2 + card_pub_mod_len] << 8) + data[3 + card_pub_mod_len]
    card_pub_exp = data[4 + card_pub_mod_len:4 + card_pub_mod_len+card_pub_exp_len]

    print(card_pub_mod_len)
    print(card_pub_mod)
    print(card_pub_exp_len)
    print(card_pub_exp)
    
    
    # cardExp,sw1,sw2 = getCardKeyExp(connection)
    # print("PubKey Exponent:",cardExp,sw1,sw2)
    # cardMod,sw1,sw2 = getCardKeyMod(connection)
    # print("PubKey Modulus:",cardMod,sw1,sw2)
    
    # cardPubKey = constructCardKey(cardMod, cardExp)
    # writeToFile = saveCardKey(cardPubKey)
    
    # generateReaderKeys()
    # readerPrivKey, readerPubKey, readerKeyMod, readerKeyExp = retrieveReaderKeys()
    
    # data, sw1, sw2 = sendPubKeyMod(connection, readerKeyMod)
    # data, sw1, sw2 = sendPubKeyExp(connection, readerKeyExp)
    
    # msg = "Testing the keys"
    # data, sw1, sw2 = constructPubKey(connection, ascii_to_hexlist(msg))
    
    
if __name__ == '__main__':
    main()