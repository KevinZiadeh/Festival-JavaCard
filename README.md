# JavaCard Project

> JavaCard Project for the Embedded Systems Security course at Ecole Polytechnique.

## Description

This project is a JavaCard applet that simulates a festival wallet. Initially the attendee will come to the welcome booth and will be given a card with a certain amount of money. The card will be used to buy food, drinks, and other items at the festival: attendee will receive a voucher confirming his purchase that they will give to the food/drink booth. In addition, the card holder can transfer his credit to another card.

The information saved on the card is the following:
- The card PIN
- The card name
- The card ID
- The card amount

If the attendee wants to add money to his card, he can go to the add money booth and give the amount of money he wants to add. The booth will then add the money to the card.


## Requirements

- JavaCard SDK
- Ant
- Python 3
- GlobalPlatformPro


## Usage

```bash
$ git clone https://github.com/KevinZiadeh/Festival-JavaCard.git
$ cd Festival-JavaCard
$ ant
```

To generate the input params for the applet, run the following command:

```bash
$ python3 Client/generate_card_setup.py
```

To install the applet on the card, you will run the command received from the previous command:

```bash
$ gp --install <applet.cap> --params <input_params>
```

Finally, you can run the Python client booth to interact with the applet:

```bash
$ python3 Client/clientSecWallet.py
```

You can add money to the card by using the provided script:

```bash
$ python3 Client/add_money.py
```