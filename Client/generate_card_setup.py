def encode_bytes(data, pad=0):
    res = data.encode("utf-8").hex()
    if pad:
        res += "00" * ((pad - len(res)//2))
    return res

def encode_short(data):
    return int(data).to_bytes(2, byteorder="big").hex()


def main():
    print("""
###############################################
#                                             #
#        Setup Portal of the Festival         #
#                                             #
###############################################
          """
    )
    
    pin = input("Enter your 4 digit PIN: ")
    if len(pin) != 4 or not pin.isdigit():
        print("Invalid PIN. Please enter a 4 digit pin")
        return

    card_name = input("Enter your card name (at most 32 characters): ")
    if len(card_name) > 32:
        print("Invalid card name. Please enter a card name with at most 32 characters")
        return
    
    card_number = input("Enter your 16 digit card number (16 digit number): ")
    if len(card_number) != 16 or not card_number.isdigit():
        print("Invalid card number. Please enter a 16 digit card number")
        return
    
    add_amount = input("Enter the amount you want to add: ")
    if not add_amount.isdigit() or int(add_amount) <= 0 or int(add_amount) > 1000:
        print("Invalid amount. A valid amount should be a positive integer and at most 1000")
        return
    
    
    encoded_pin = encode_bytes(pin)
    encoded_card_name = encode_bytes(card_name, 32)
    encoded_card_number = encode_bytes(card_number)
    encoded_add_amount = encode_short(add_amount)

    print(f"""
========================================
PIN: {pin}
Card Name: {card_name}
Card Number: {card_number}

To initialize the card, please enter the following commands in the terminal:

gp --install ./SecWalllet221.cap --params {encoded_pin}{encoded_card_name}{encoded_card_number}{encoded_add_amount}

========================================
    """)
    return

if __name__ == "__main__":
    main()