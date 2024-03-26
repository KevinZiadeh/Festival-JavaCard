from instructions import SELECT, AID, CLA, UNBLOCK_INS
from helpers import wait_for_card, validate_status, encode_bytes


welcome_message = """
###############################################
#                                             #
#          Card Unblocking Portal             #
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
            print("There was an error with your card. Please go to the nearest branch for assistance")
            return
    
        validate = input("Are you sure you want to unblock your card? (y/n): ")
        if validate.lower() == "n":
            return
        
        secret = "Kevin"
        _, sw1, sw2 = connection.transmit([CLA, UNBLOCK_INS, 0x00, 0x00, 0x00] + list(map(ord, secret)))
        if validate_status(sw1, sw2):
            print("Card unblocked successfully")
        
    except Exception as e:
        print("Exception")
        print(e)
        print("Unable to unblock your card. Card disconnected")  
    
    except KeyboardInterrupt:
        pass
    

if __name__ == "__main__":
    main()
