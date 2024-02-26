import time
from smartcard.System import readers


SELECT = [0x00,0xA4,0x04,0x00,0x08]
AID = [0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08]
CLA   = 0xB0
GET_INFO_INS = 0x00
VERIFY_PIN_INS = 0x01

banner = """
==========================
        Festival ATM 
0 - Show Banner
1 - Show Card Info
2 - Check Balance
# 3 - Deposit
9 - Exit
==========================
        """
        
def validateStatus(sw1, sw2):
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


def prepareData(data):
    return [ord(str(e)) for e in data]

        
def getCardConnection():
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


def validatePin(connection, pin_validated):
    if pin_validated:
        print("Pin already validated")
        return True
    
    pin = input("Please enter your pin: ")
    if len(pin) != 4:
        print("Invalid PIN. Please enter a 4 digit pin")
        return False
    
    try:
        data, sw1, sw2 = connection.transmit([CLA, VERIFY_PIN_INS, 0x00, 0x00, 0x4] + prepareData(pin))
    except:
        print("Invalid PIN. Please enter a 4 digit pin")
        return False
    
    if validateStatus(sw1, sw2):
        return True


def getCardInfo(connection, card_name, card_number):
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

def getBalance(connection):
    data, sw1, sw2 = connection.transmit([CLA, 0x10, 0x00, 0x00, 0x00, 0x02])

    if validateStatus(sw1, sw2):    
        balance = (data[0] << 8) + data[1]
        print(f"Your balance is: {balance}")
    





INSTRUCTION_CHOICE_MAP = {
	2: getBalance,
}
def main():

    print("""
###############################################
#                                             #
#        Welcome to the Festival              #
#                                             #
###############################################
Insert Card...""")
    
    connection = None
    while True:
        try:
            connection = getCardConnection()
            pin_validated = False

            #Selection AID
            data, sw1, sw2 = connection.transmit(SELECT + AID)
            if sw1 != 0x90 and sw2 != 0x00:
                print("There was an error with your card. Please go to the nearest branch for assistance")
                break
        
            card_name = ""
            card_number = ""
            card_name, card_number = getCardInfo(connection, card_name, card_number)
            if not card_name or not card_number:
                print("There was an error with your card. Please go to the nearest branch for assistance")
                break
                        
            while not pin_validated:
                pin_validated = validatePin(connection, pin_validated)
        
            print(banner)
            while True:
                    choice = input("\nPlease input the type of operation: ")
                    try:
                        handler = INSTRUCTION_CHOICE_MAP.get(int(choice))
                    except:
                        print("Invalid Choice")
                        continue
                    if handler:
                        handler(connection)
                    elif choice == "0":
                        print(banner)
                    elif choice == "1":
                        card_name, card_number = getCardInfo(connection, card_name, card_number)
                    elif choice == "9":
                        if connection:
                            connection.disconnect() 
                            print("\nPlease remove your card")
                            time.sleep(5)
                        break
                    else:
                        print("Invalid Choice")
        
        
        
        except KeyboardInterrupt:
            if connection:
                connection.disconnect() 
                print("\nCard Disconnected...")
            print("\nExiting...\n")
            break
        
    print("""
###############################################
#                                             #
#        We Hope You Had A Great Time         #
#                                             #
###############################################
          """)

if __name__ == "__main__":
    main()
