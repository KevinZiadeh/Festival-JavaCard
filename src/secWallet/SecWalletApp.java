package secWallet;

import javacard.framework.APDU;
import javacard.framework.Applet; // https://docs.oracle.com/javacard/3.0.5/api/javacard/framework/Applet.html
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN; // https://docs.oracle.com/javacard/3.0.5/api/javacard/framework/OwnerPIN.html
import javacard.security.*;
import javacardx.crypto.*;

public class SecWalletApp extends Applet {
    public static final byte CLA_MONAPPLET = (byte) 0xB0;

    /* INSTRUCTIONS */
    public static final byte INS_GET_INFO = (byte) 0x00;
    public static final byte INS_VERIFY_PIN = (byte) 0x01;
    public static final byte INS_GET_BALANCE = (byte) 0x10;
    public static final byte INS_CREDIT = (byte)0x20;
    public static final byte INS_DEBIT = (byte)0x30;
    	

    /* ATTRIBUTES */
    OwnerPIN pin;
    private Signature signature;
    private KeyPair keyPair;
    //private RSAPublicKey publicKey;
    
    short card_amount;
    private static byte[] card_user_name;
    private static byte[] num_participant;

    /* PIN SPECS */
    public static final byte MAX_PIN_SIZE = (byte) 0x04;
    public static final byte PIN_TRY_LIMIT = (byte) 0x05;
    
    /* BALANCE CONFIG */
    public static final short MAX_BALANCE = 1000;
    public static final short MAX_INPUT_AMOUNT = 500;
    public static final short MAX_DEBIT_AMOUNT = 200;

    
    /* SW CODES */
    public static final short SW_VERIFICATION_FAILED = 0x6300; 
    public static final short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
    public static final short SW_MAX_BALANCE = 0x6400;
    public static final short SW_NEG_BALANCE = 0x6401;
    public static final short SW_INVALID_INPUT = 0x6402;


    /* Constructor */
    private SecWalletApp(byte bArray[], short bOffset, byte bLength) {
        pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE); // Create User PIN

        byte iLen = bArray[bOffset]; // AID length
        bOffset = (short)(bOffset + iLen + 1);
        byte cLen = bArray[bOffset]; // info length
        bOffset = (short)(bOffset + cLen + 1);
        byte aLen = bArray[bOffset]; // applet data length

        pin.update(bArray, (short)(bOffset + 1), (byte) 0x04);


        card_user_name = new byte[(short) 32];
        Util.arrayCopy(bArray, (short) (bOffset + 5), card_user_name, (short) 0, (byte) card_user_name.length);
        
        num_participant = new byte[(short) 16];
        Util.arrayCopy(bArray, (short) (bOffset + 5 + 32), num_participant, (short) 0, (byte) num_participant.length);
        
        card_amount = Util.getShort(bArray, (short) (bOffset + 5 + 32 + 16));
        
        keyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1024);
        keyPair.genKeyPair();
        signature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
        
        //Not too sure how this is gonna work 
        byte[] publicKey = new byte[128]; // Adjust size as per your key size
        short publicKeyLength = keyPair.getPublic().getExponent(publicKey, (short) 0);
        keyPair.getPublic().getModulus(publicKey, (short) publicKeyLength);
        
        //we could do this to send the public key upon inserting the card
        
    }

    public static void install(byte bArray[], short bOffset, byte bLength) throws ISOException {
        new SecWalletApp(bArray, bOffset, bLength).register();
    }

    public boolean select() {
        if (pin.getTriesRemaining() == 0)
            return false;
        return true;
    }

    public void deselect() {
        pin.reset();
    }
    
    private void verifyPin(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte byteRead = (byte) (apdu.setIncomingAndReceive());

        if (pin.check(buffer, ISO7816.OFFSET_CDATA, byteRead) == false) {
            ISOException.throwIt(SW_VERIFICATION_FAILED);
        }
    } 
    
    public void process(APDU apdu) throws ISOException {
        byte buf[] = apdu.getBuffer();

        if (this.selectingApplet()) return;

        if (buf[ISO7816.OFFSET_CLA] != CLA_MONAPPLET) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        switch (buf[ISO7816.OFFSET_INS]) {
            case INS_GET_INFO:
            	getInfo(apdu);
            	break;
            case INS_VERIFY_PIN:
            	verifyPin(apdu);
            	break;
            case INS_DEBIT:
            	if (!pin.isValidated()) ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
            	debit(apdu);
            	break;
            case INS_CREDIT:
            	if (!pin.isValidated()) ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
            	credit(apdu);
            	break;
            case INS_GET_BALANCE:
                if (!pin.isValidated()) ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
                getBalance(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                break;
        }
    }
    
    private void getInfo(APDU apdu) {
        byte buffer[] = apdu.getBuffer();

        Util.arrayCopyNonAtomic(num_participant,
            (short) 0,
            buffer,
            (short) 0,
            (short) num_participant.length);
        Util.arrayCopyNonAtomic(card_user_name,
            (short) 0,
            buffer,
            (short) num_participant.length,
            (short) card_user_name.length);
        apdu.setOutgoingAndSend((short) 0, (short)(num_participant.length + card_user_name.length));
//        
//        Util.setShort(buffer, (short) (short)(num_participant.length + card_user_name.length) + 1, (short) 999);
//        apdu.setOutgoingAndSend((short) 0, (short)(num_participant.length + card_user_name.length + 4));

    }

    private void getBalance(APDU apdu) {
        byte buffer[] = apdu.getBuffer();
        
        Util.setShort(buffer, (short) 0, card_amount);
        apdu.setOutgoingAndSend((short) 0, (short) 2);
        
        
//        short Le = apdu.setOutgoing();
//        if(Le < 2) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
//        apdu.setOutgoingLength((byte) 2);
//        Util.setShort(buffer, (short) 0, (short) 999);
//        buffer[0] = (byte)1;
//        buffer[1] = (byte)2;
//        apdu.sendBytes((short) 0, (short)2);

        
    }
    
    private void credit(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        byte numBytes = buf[ISO7816.OFFSET_LC];
        byte read = (byte)apdu.setIncomingAndReceive();
        
        if (numBytes < 1 || numBytes > 2 || read < 1 || read > 2) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
       
        short input_amount = Util.getShort(buf, (short) ISO7816.OFFSET_CDATA);
        
        if (input_amount < 0 || input_amount > MAX_INPUT_AMOUNT) ISOException.throwIt(SW_INVALID_INPUT); 
                
        if ((short) (card_amount + input_amount) > MAX_BALANCE) ISOException.throwIt(SW_MAX_BALANCE); 
        
        card_amount = (short) (card_amount + input_amount);
        
        //Not too sure we want to do signing when adding money 
        //also where is the verification of the signature supposed to happen, maybe at the terminal level or vice versa
        //either terminal(reader or client) signs its transaction and the card verifies the signature before taking money in
        //or out
    } 
    
    private void debit(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        byte numBytes = buf[ISO7816.OFFSET_LC];
        byte read = (byte)apdu.setIncomingAndReceive();
        
        if (numBytes < 1 || numBytes > 2 || read < 1 || read > 2) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
       
        short debit_amount = Util.getShort(buf, (short) ISO7816.OFFSET_CDATA);
        
        if (debit_amount < 0 || debit_amount > MAX_DEBIT_AMOUNT) ISOException.throwIt(SW_INVALID_INPUT); 
                
        if ((short) (card_amount + debit_amount) > MAX_BALANCE) ISOException.throwIt(SW_MAX_BALANCE); 
        
        card_amount = (short) (card_amount + debit_amount);
        
        signature.init(keyPair.getPrivate(), Signature.MODE_SIGN);
        short signatureLength = signature.sign(buf, ISO7816.OFFSET_CDATA, length, buf, (short) 0);
        
        //send the signature back to the terminal 
        apdu.setOutgoing();
        apdu.setOutgoingLength(signatureLength);
        apdu.sendBytesLong(buf, (short) 0, signatureLength);
    }

}