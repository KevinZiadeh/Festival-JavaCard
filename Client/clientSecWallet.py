import time
from Client.instructions import print_card_info, wait_for_card, get_balance, validate_status


SELECT = [0x00,0xA4,0x04,0x00,0x08]
AID = [0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08]
CLA   = 0xB0
VERIFY_PIN_INS = 0x01

banner = """
==========================
        Festival ATM 
0 - Show Banner
1 - Show Card Info
2 - Check Balance
3 - Buy Drinks (10)
4 - Buy Food (20)
5 - Buy Tickets (50)
9 - Exit
==========================
        """
        
def prepareData(data):
    return [ord(str(e)) for e in data]


def validatePin(connection, pin_validated):
    if pin_validated:
        print("Pin already validated")
        return True
    
    pin = input("Please enter your pin: ")
    if len(pin) != 4:
        print("Invalid PIN. Please enter a 4 digit pin")
        return False
    
    try:
        _, sw1, sw2 = connection.transmit([CLA, VERIFY_PIN_INS, 0x00, 0x00, 0x4] + prepareData(pin))
    except:
        print("Invalid PIN. Please enter a 4 digit pin")
        return False
    
    if validate_status(sw1, sw2):
        return True
    

INSTRUCTION_CHOICE_MAP = {
	2: get_balance,
}
def main():
    welcome_message = """
###############################################
#                                             #
#        Welcome to the Festival              #
#                                             #
###############################################
Insert Card..."""

    
    connection = None
    while True:
        print(welcome_message)
        try:
            connection = wait_for_card()
            pin_validated = False

            #Selection AID
            _, sw1, sw2 = connection.transmit(SELECT + AID)
            if sw1 != 0x90 and sw2 != 0x00:
                raise Exception("There was an error with your card. Please go to the nearest branch for assistance")
        
            card_name = ""
            card_number = ""
            card_name, card_number = print_card_info(connection, card_name, card_number)
            if not card_name or not card_number:
                raise Exception("There was an error with your card. Please go to the nearest branch for assistance")
                        
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
                        card_name, card_number = print_card_info(connection, card_name, card_number)
                    elif choice == "9":
                        if connection:
                            connection.disconnect() 
                            print("\nPlease remove your card")
                            time.sleep(5)
                        break
                    else:
                        print("Invalid Choice")
        
        except Exception as e:
            print(e)
            if connection:
                connection.disconnect() 
                print("\nPlease remove your card")
            time.sleep(5)
        
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
