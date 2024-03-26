import time
from helpers import encode_short, short_to_byte_array, prepareData, validate_status, wait_for_card_removed, signMessage, verifySignature
from Crypto.PublicKey.RSA import construct

SELECT = [0x00,0xA4,0x04,0x00,0x08]
AID = [0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08]
CLA   = 0xB0
GET_INFO_INS = 0x00
VERIFY_PIN_INS = 0x01
UNBLOCK_INS = 0x02
GET_BALANCE_INS = 0x10
CREDIT_INS = 0x20
DEBIT_INS = 0x30
SEND_READER_PUBKEY_MOD = 0x50
SEND_READER_PUBKEY_EXP = 0x51
CREATE_CARD_READER_PUBKEY = 0x52
GET_CARD_PUBKEY = 0x60

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
        # balance = (data[0] << 8) + data[1]
        balance = int.from_bytes(bytes(data), 'big')
        print(f"Your balance is: {balance}")
        

def key_exchange(connection, reader_pub_key):
    data, sw1, sw2 = connection.transmit([CLA, GET_CARD_PUBKEY, 0x00, 0x00, 0x00])
    card_pub_mod_len = int.from_bytes(bytes(data[0:2]), 'big')
    card_pub_mod = data[2:card_pub_mod_len+2]
    card_pub_exp_len = int.from_bytes(bytes(data[2 + card_pub_mod_len:4 + card_pub_mod_len]), 'big')
    card_pub_exp = data[4 + card_pub_mod_len:4 + card_pub_mod_len+card_pub_exp_len]
    card_pub_mod = int.from_bytes(bytes(card_pub_mod), 'big')
    card_pub_exp = int.from_bytes(bytes(card_pub_exp), 'big')
   
    card_pubKey = construct((card_pub_mod, card_pub_exp))
   
    n = list(reader_pub_key.n.to_bytes(128,byteorder='big'))
    e = list(reader_pub_key.e.to_bytes(128,byteorder='big'))

    data, sw1, sw2 = connection.transmit([CLA, SEND_READER_PUBKEY_MOD, 0x00, 0x00, len(n)] + n)
    if not validate_status(sw1, sw2):
        print('Error while transmitting modulus')
        print(hex(sw1), hex(sw2))
        return False
    data, sw1, sw2 = connection.transmit([CLA, SEND_READER_PUBKEY_EXP, 0x00, 0x00, len(n)] + e)
    if not validate_status(sw1, sw2):
        print('Error while transmitting exponent')
        print(hex(sw1), hex(sw2))
        return False
    data, sw1, sw2 = connection.transmit([CLA, CREATE_CARD_READER_PUBKEY, 0x00, 0x00])
    if not validate_status(sw1, sw2):
        print('Error while card creates key')
        print(hex(sw1), hex(sw2))
        return False

    return card_pubKey

def debit_amount(connection, amount, priv_key, pub_key):
    encoded_amount = short_to_byte_array(encode_short(amount))
    signature = signMessage(encoded_amount, priv_key)
    message = encoded_amount + signature
    data, sw1, sw2 = connection.transmit([CLA, DEBIT_INS, 0x00, 0x00, len(message)] + message)
    
    value = int.from_bytes(bytes(data), 'big')
    if not validate_status(sw1, sw2):
        return False

    data, signature = data[:2], data[2:]
    received_value = int.from_bytes(bytes(data), 'big')
    if received_value != amount:
        print("There was an error with your card. Please go to the nearest branch for assistance")
        return False
    elif verifySignature(data, signature, pub_key):
        get_balance(connection)
        return True
    else:
        print("Transaction failed. Please go to the nearest branch for assistance")
        return False

def credit_amount(connection, amount, priv_key, pub_key):
    encoded_amount = short_to_byte_array(encode_short(amount))
    signature = signMessage(encoded_amount, priv_key)
    message = encoded_amount + signature
    data, sw1, sw2 = connection.transmit([CLA, CREDIT_INS, 0x00, 0x00, len(message)] + message)
    
    value = int.from_bytes(bytes(data), 'big')
    if not validate_status(sw1, sw2):
        return False

    data, signature = data[:2], data[2:]
    received_value = int.from_bytes(bytes(data), 'big')

    if received_value != amount:
        print(received_value, amount, type(received_value), type(amount))
        print("There was an error with your card. Please go to the nearest branch for assistance")
        return False
    elif verifySignature(data, signature, pub_key):
        get_balance(connection)
        print("Transaction successful.")
        return True
    else:
        print(verifySignature(data, signature, pub_key))
        print("Transaction failed. Please go to the nearest branch for assistance")
        return False

def transfer_credit(connection, card_num, reader_pub_key, priv_key, pub_key):
    amount = input("Enter the amount you want to transfer: ")
    if not amount.isdigit():
        print("Invalid amount. Please enter a valid amount")
        return False

    debit = debit_amount(connection, int(amount), priv_key, pub_key)
    if not debit:
        print("There was an error while transferring money. Please try again")
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
                
        pub_key = key_exchange(connection, reader_pub_key)
        if not pub_key:
            print("There was an error with your card. Please go to the nearest branch for assistance")
            return True
        
        credit = credit_amount(connection, int(amount), priv_key, pub_key)
        if not credit:
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
        
    
def reimburse_credit(connection, card_num, priv_key, pub_key):
    try:
        with open("reimbursement.txt", "r") as f:
            content = f.read()
            for line in content.split("\n"):
                if card_num in line:
                    print(f"You have a reimbursement of: {line.split()[1]}")
                    proceed = input("Do you want to proceed with the reimbursement? (y/n): ")
                    if proceed.lower() == "n":
                        return
                    
                    amount = int(line.split()[1])
                    credit = credit_amount(connection, amount, priv_key, pub_key)
                    if not credit:
                        print("Reimbursement unsuccessful. Please try again.")
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
        