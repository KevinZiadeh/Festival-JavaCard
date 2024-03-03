import time
from instructions import print_card_info, get_balance, transfer_credit, reimburse_credit, validate_pin, SELECT, AID
from helpers import wait_for_card, wait_for_card_removed

banner = """
==========================
        Festival ATM 
0 - Show Banner
1 - Show Card Info
2 - Check Balance
3 - Buy Drinks (10)
4 - Buy Food (20)
5 - Buy Tickets (50)
6 - Start Credit Transfer
7 - Reimburse Credit
9 - Exit
==========================
        """
        
welcome_message = """
###############################################
#                                             #
#        Welcome to the Festival              #
#                                             #
###############################################
Insert Card..."""
ending_message = """
###############################################
#                                             #
#        We Hope You Had A Great Time         #
#                                             #
###############################################
\n\n\n\n\n\n\n\n\n\n
          """
          
def heartbeat(connection):
    try:
        connection.getATR()
        return True
    except:
        print("Card Removed...")
        connection.disconnect()
        return False
    

            
def main():
    connection = None
    while True:
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
                        
            valid = validate_pin(connection)
            if not valid:
                connection.disconnect()
                time.sleep(1)
                continue
        
            print(banner)
            while True:
                if not heartbeat(connection):
                    time.sleep(1)
                    break
                choice = input("\nPlease input the type of operation: ")
                if not heartbeat(connection):
                    time.sleep(1)
                    break
                if choice == "0":
                    print(banner)
                elif choice == "1":
                    card_name, card_number = print_card_info(connection, card_name, card_number)
                elif choice == "2":
                    get_balance(connection)
                elif choice == "6":
                    reset = transfer_credit(connection, card_number)
                    if reset:
                        connection.disconnect()
                        break
                elif choice == "7":
                    reimburse_credit(connection, card_number)
                elif choice == "9":
                    print("\nPlease remove your card")
                    wait_for_card_removed(connection)
                    print(ending_message)
                    break
                else:
                    print("Invalid Choice")
        
        except Exception as e:
            print("Exception")
            print(e)
            print("\nPlease remove your card")
            wait_for_card_removed(connection)
            print(ending_message)
            time.sleep(1)
        
        except KeyboardInterrupt:
            print("\nExiting...\n")
            break
        
    print(ending_message)

if __name__ == "__main__":
    main()
