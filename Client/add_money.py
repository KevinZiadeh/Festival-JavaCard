from instructions import print_card_info, get_balance, validate_pin, credit_amount, key_exchange, SELECT, AID
from helpers import wait_for_card, generateReaderKeys


welcome_message = """
###############################################
#                                             #
#        Add Money to Card Portal             #
#                                             #
###############################################
Insert Card..."""

def main():
    reader_priv_key, reader_pub_key = generateReaderKeys()
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

        card_pub_key = key_exchange(connection, reader_pub_key)

        if not card_pub_key:
            raise Exception("There was an error with your card. Please go to the nearest branch for assistance")
        
        get_balance(connection)
        
        add_amount = input("Enter the amount you want to add: ")
        if not add_amount.isdigit() or int(add_amount) <= 0 or int(add_amount) > 500:
            print("Invalid amount. A valid amount should be a positive integer and at most 500")
            return

        credit_amount(connection, int(add_amount), reader_priv_key, card_pub_key)

    except Exception as e:
        print("Exception")
        print(e)    

    except KeyboardInterrupt:
        pass
    


if __name__ == "__main__":
    main()
