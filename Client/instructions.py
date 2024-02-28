import time
from smartcard.System import readers

CLA   = 0xB0
GET_INFO_INS = 0x00
GET_BALANCE_INS = 0x10

def wait_for_card():
    while True:
        try:
            r = readers()
            connection=r[0].createConnection()
            connection.connect()
            print("Card Detected...")
            return connection
        except:
            time.sleep(5)
            continue

def print_card_info(connection, card_name, card_number):
    if card_name and card_number:
        print(f"""
========================================
Hello {card_name}, 
Your card number is {card_number}
========================================
            """)
    else:
        data, sw1, sw2 = connection.transmit([CLA, GET_INFO_INS, 0x00, 0x00])

        if sw1 != 0x90 and sw2 != 0x00:
            return "", ""
        else:
            card_name = ''.join(chr(decimal) for decimal in data[16:]).strip()
            card_number = ''.join(chr(decimal) for decimal in data[0:16]).strip()
            print(f"""
========================================
Hello {card_name}, 
Your card number is {card_number}
========================================
            """)
            
    return card_name, card_number
    
    
def get_balance(connection):
    data, sw1, sw2 = connection.transmit([CLA, GET_BALANCE_INS, 0x00, 0x00, 0x00, 0x02])

    if validate_status(sw1, sw2):    
        balance = (data[0] << 8) + data[1]
        print(f"Your balance is: {balance}")
        
def validate_status(sw1, sw2):
    status = False

    # Check PIN
    if(sw1 == 0x63 and sw2 == 0x00):
        print("PIN verification failed. Please try again.")
    elif(sw1 == 0x63 and sw2 == 0x01):
        print("PIN verification is required.")
    elif(sw1 == 0x64 and sw2 == 0x00):
        print("Maximum balance of 1000 exceeded.")
    elif(sw1 == 0x64 and sw2 == 0x01):
        print("Cannot process transaction, not enough funds.")
    elif(sw1 == 0x64 and sw2 == 0x02):
        print("You cannot deposit more than 500, or less than 0, at a time.")
    elif(sw1 == 0x90 and sw2 == 0x00):
        status = True

    return status

