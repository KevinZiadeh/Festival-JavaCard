import time
from smartcard.System import readers
from helpers import encode_short, short_to_byte_array, prepareData, validate_status, wait_for_card_removed

SELECT = [0x00,0xA4,0x04,0x00,0x08]
AID = [0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08]
CLA   = 0xB0
GET_INFO_INS = 0x00
VERIFY_PIN_INS = 0x01
UNBLOCK_INS = 0x02
GET_BALANCE_INS = 0x10
CREDIT_INS = 0x20
DEBIT_INS = 0x30


def validate_pin(connection):
    while True:       
        pin = input("Please enter your pin: ")
        if len(pin) != 4:
            print("Invalid PIN. Please enter a 4 digit pin")
            continue
        
        sw1, sw2 = 0, 0
        try:
            _, sw1, sw2 = connection.transmit([CLA, VERIFY_PIN_INS, 0x00, 0x00, 0x4] + prepareData(pin))
            if not validate_status(sw1, sw2):
                continue
            break
        except Exception as e:
            if sw1 == 0x00 and sw2 == 0x00:
                print("Card disconnected...")
                return False 
            print(e)
            continue

    return True


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
        

def transfer_credit(connection, card_num):
    amount = input("Enter the amount you want to transfer: ")
    encoded_amount = short_to_byte_array(encode_short(amount))
    data, sw1, sw2 = connection.transmit([CLA, DEBIT_INS, 0x00, 0x00, 0x02] + encoded_amount)
    if not validate_status(sw1, sw2):
        return False
    elif "".join([chr(i) for i in data]) != "OK": # When we debit or credit, we validate the status and check the response
        print("There was an error adding money to your card. Please try again")
        return False
    with open("reimbursement.txt", "a") as f:
        f.write(f"{card_num} {amount}\n")
    print("""
========================================
You will initiate a transfer of credit 
to another card.
The other card must be present and 
inserted into the reader within
10 seconds after you remove your card.
========================================
       """)
    time.sleep(1)
    print("Remove your card...")
    wait_for_card_removed(connection)
    print("Insert the other card...")
    counter = 0
    while True:
        try:
            connection.connect()
            print("Card Detected...")
            break
        except:
            time.sleep(1)
            counter += 1
            if counter == 10:
                print("No card detected after 10 seconds. Select the reimbursement option to get your money back.")
                return True
            
    try:  
        _, sw1, sw2 = connection.transmit(SELECT + AID)
        if sw1 != 0x90 and sw2 != 0x00:
            print("There was an error with your card. Please go to the nearest branch for assistance")
            return True
     
        validate_pin(connection)
                
        data, sw1, sw2 = connection.transmit([CLA, CREDIT_INS, 0x00, 0x00, 0x02] + encoded_amount)
        if not validate_status(sw1, sw2):
            print("Transfer unsuccessful. Select the reimbursement option to get your money back.")
            return True

        print("Transfer successful.")
        with open("reimbursement.txt", "r") as f:
            content = f.read()
            with open("reimbursement.txt", "w") as f:
                f.write(content.replace(f"{card_num} {amount}\n", ""))
        return True
            
    except Exception as e:
        print("Instuction Exception")
        print(e)
        print("\nPlease remove your card")
        wait_for_card_removed(connection)
        return True
        
    except KeyboardInterrupt:
        print("Transfer unsuccessful. Select the reimbursement option to get your money back.")
        return True
        
    
def reimburse_credit(connection, card_num):
    try:
        with open("reimbursement.txt", "r") as f:
            content = f.read()
            for line in content.split("\n"):
                if card_num in line:
                    print(f"You have a reimbursement of: {line.split()[1]}")
                    proceed = input("Do you want to proceed with the reimbursement? (y/n): ")
                    if proceed.lower() == "n":
                        return
                    
                    data, sw1, sw2 = connection.transmit([CLA, CREDIT_INS, 0x00, 0x00, 0x02] + short_to_byte_array(encode_short(line.split()[1])))
                    if not validate_status(sw1, sw2):
                        return
                    elif "".join([chr(i) for i in data]) != "OK": # When we debit or credit, we validate the status and check the response
                        print("There was an error adding money to your card. Please try again")
                        return
                    else:
                        print("Reimbursement successful.")
                        with open("reimbursement.txt", "w") as f:
                            f.write(content.replace(f"{card_num} {line.split()[1]}\n", ""))
                            get_balance(connection)
                        return
            print("You do not have any pending reimbursements.")
    except:
        print("You do not have any pending reimbursements.")
        