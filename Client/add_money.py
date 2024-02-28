import time
from Client.instructions import print_card_info, wait_for_card, get_balance, validate_status


SELECT = [0x00,0xA4,0x04,0x00,0x08]
AID = [0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08]
CLA   = 0xB0
ADD_MONEY_INS = 0x20
    

def encode_short(data):
    return int(data).to_bytes(2, byteorder="big").hex()


def main():
    welcome_message = """
###############################################
#                                             #
#        Add Money to Card Portal             #
#                                             #
###############################################
Insert Card..."""

    
    connection = None
    print(welcome_message)
    try:
        connection = wait_for_card()

        #Selection AID
        _, sw1, sw2 = connection.transmit(SELECT + AID)
        if sw1 != 0x90 and sw2 != 0x00:
            raise Exception("There was an error with your card. Please go to the nearest branch for assistance")
    
        card_name = ""
        card_number = ""
        card_name, card_number = print_card_info(connection, card_name, card_number)
        if not card_name or not card_number:
            raise Exception("There was an error with your card. Please go to the nearest branch for assistance")
        
        add_amount = input("Enter the amount you want to add: ")
        if not add_amount.isdigit() or int(add_amount) <= 0 or int(add_amount) > 500:
            print("Invalid amount. A valid amount should be a positive integer and at most 500")
            return
        
        add_amount_encoded = encode_short(add_amount)
        _, sw1, sw2 = connection.transmit([CLA, ADD_MONEY_INS, 0x00, 0x00, 0x02] | \
            [add_amount_encoded[i:i+2] for i in range(0, len(add_amount_encoded), 2)])
        validate_status(sw1, sw2)
        
        get_balance(connection)
            
        
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
        

if __name__ == "__main__":
    main()
