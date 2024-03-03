from instructions import print_card_info, get_balance, validate_pin, SELECT, AID, CLA, CREDIT_INS
from helpers import wait_for_card, short_to_byte_array, encode_short, validate_status


welcome_message = """
###############################################
#                                             #
#        Add Money to Card Portal             #
#                                             #
###############################################
Insert Card..."""

def main():
    connection = None
    print(welcome_message)
    try:
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
        
        validate_pin(connection)
        
        get_balance(connection)
        
        add_amount = input("Enter the amount you want to add: ")
        if not add_amount.isdigit() or int(add_amount) <= 0 or int(add_amount) > 500:
            print("Invalid amount. A valid amount should be a positive integer and at most 500")
            return
        
        add_amount_encoded = short_to_byte_array(encode_short(add_amount))
        data, sw1, sw2 = connection.transmit([CLA, CREDIT_INS, 0x00, 0x00, 0x02] + add_amount_encoded)
        if not validate_status(sw1, sw2):
            return
        elif "".join([chr(i) for i in data]) != "OK": # When we debit or credit, we validate the status and check the response
            print("There was an error adding money to your card. Please try again")
        else:
            get_balance(connection)
            
        
    except Exception as e:
        print("Exception")
        print(e)    

    except KeyboardInterrupt:
        pass
    


if __name__ == "__main__":
    main()
