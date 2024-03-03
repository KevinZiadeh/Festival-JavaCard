import time
from smartcard.System import readers

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
    elif(sw1 == 0x90 and sw2 == 0x00):
        status = True

    return status

