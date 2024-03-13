import time
from smartcard.System import readers
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
from Crypto.Signature import pkcs1_15

def encode_short(data):
    return int(data).to_bytes(2, byteorder="big").hex()

def short_to_byte_array(data):
    return [int(data[i:i+2], 16) for i in range(0, len(data), 2)]

def encode_bytes(data, pad=0):
    res = data.encode("utf-8").hex()
    if pad:
        res += "00" * ((pad - len(res)//2))
    return res

def prepareData(data):
    return [ord(str(e)) for e in data]

def wait_for_card():
    while True:
        try:
            r = readers()
            connection=r[0].createConnection()
            connection.connect()
            return connection
        except:
            time.sleep(1)
            continue

def wait_for_card_removed(connection):
    try:
        while connection.getATR():
            time.sleep(1)
    except:
        connection.disconnect()
        
def validate_status(sw1, sw2):
    status = False

    # Check PIN
    if(sw1 == 0x63 and sw2 == 0x00):
        print("PIN verification failed. Please try again.")
    elif(sw1 == 0x63 and sw2 == 0x01):
        print("PIN verification is required.")
    elif(sw1 == 0x63 and sw2 == 0x02):
        print("PIN attempts exceeded. Card blocked. Please go to the nearest branch for assistance.")
    elif(sw1 == 0x63 and sw2 == 0x03):
        print("Unable to unblock your card. Card is not blocked.")
    elif(sw1 == 0x64 and sw2 == 0x00):
        print("Maximum balance of 1000 exceeded.")
    elif(sw1 == 0x64 and sw2 == 0x01):
        print("Cannot process transaction, not enough funds.")
    elif(sw1 == 0x64 and sw2 == 0x02):
        print("You cannot deposit more than 500, or less than 0, at a time.")
    elif(sw1 == 0x64 and sw2 == 0x03):
        print("You cannot debit more than 200, or less than 0, at a time.")
    elif(sw1 == 0x94 and sw2 == 0x84):
        print("Signature verification failed. Please try again.")
    elif(sw1 == 0x90 and sw2 == 0x00):
        status = True

    return status


def generateReaderKeys():
    privateKey = RSA.generate(1024)
    with open('reader_privKey.pem', 'wb') as file:
        file.write(privateKey.exportKey())
        
    publicKey = privateKey.publickey()
    with open('reader_pubKey.pem', 'wb') as file:
        file.write(publicKey.exportKey())

    return privateKey, publicKey
        
# Not used
def retrieveReaderKeys(): 
    with open('reader_privKey.pem', 'rb') as file:
        reader_privKey = RSA.importKey(file.read())
        
    with open('reader_pubKey.pem', 'rb') as file: 
        reader_pubKey = RSA.importKey(file.read())

    print(reader_privKey)
        
    return reader_privKey, reader_pubKey


def signMessage(message, key):
    hash = SHA.new(bytes(message))
    signature = pkcs1_15.new(key).sign(hash)
    return list(signature)

def verifySignature(message, signature, key):
    message = bytes(message)
    hash = SHA.new(message)
    signature = bytes(signature)
    try:
        pkcs1_15.new(key).verify(hash, signature)
        return True
    except (ValueError, TypeError):
        return False