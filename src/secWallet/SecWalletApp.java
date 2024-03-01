package secWallet;

//import java.security.KeyPair;
//import java.security.Signature;
//import java.security.interfaces.RSAPublicKey;

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
    public static final byte READER_PUBKEY_MOD = (byte)0x50;
    public static final byte READER_PUBKEY_EXP = (byte)0x51;
    public static final byte CARD_PUBKEY_MOD = (byte)0x60; 
    public static final byte CARD_PUBKEY_EXP = (byte)0x61;

    /* ATTRIBUTES */
    OwnerPIN pin;
    private Signature signature;
    private KeyPair keyPair;
    private RSAPrivateCrtKey privateKey;
    private RSAPublicKey publicKey;
    private RSAPublicKey reader_pubKey;
    //private RSAPublicKey publicKey;
    
    short card_amount;
    private static byte[] card_user_name;
    private static byte[] num_participant;
    
    /* SIGNATURE ATTRIBUTES */
    private static byte[] READER_KEY_MOD;
    private static byte[] READER_KEY_EXP;
    private static byte[] CARD_KEY_MOD; 
    private static byte[] CARD_KEY_EXP;
    private static byte[] MSG;
    // Signed message from card 
    private static byte[] SIGNED_MSG;
    //Signed message from reader 
    private static byte[] MSG_AND_SIG;

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
    	SIGNED_MSG = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_DESELECT);
    	MSG_AND_SIG = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_DESELECT);
    	READER_KEY_MOD = new byte[128]; 
        READER_KEY_EXP = new byte[10];
        MSG = new byte[256];
        
        signature = null;
        keyPair = null;
        privateKey = null;
        publicKey = null;
        reader_pubKey = null;
        
    	
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
    
    public void getReaderKeyMod(APDU apdu) {
    	byte[] buffer = apdu.getBuffer(0);
    	short bytesRead = 0;
    	short readOffset = 0;
    	short numBytes = (short) buffer[ISO7816.OFFSET_LC];
    	
    	bytesRead = apdu.setIncomingAndReceive();
    	
    	while (bytesRead > 0) {
    		Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, READER_KEY_MOD, readOffset, bytesRead);
    		readOffset += bytesRead;
            bytesRead = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
    	}
    }
    
    public void getReaderKeyExp(APDU apdu) {
    	  byte[] buffer = apdu.getBuffer();
    	  short numBytes = (short) buffer[ISO7816.OFFSET_LC];

    	  apdu.setIncomingAndReceive();
    	  Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, READER_KEY_EXP, (short) 0, numBytes);
    }
    
    public void constructReaderKey(APDU apdu) {
    	byte[] buffer = apdu.getBuffer();
  	  	short numBytes = (short) buffer[ISO7816.OFFSET_LC];
  	  	
  	  	reader_pubKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024, false);
  	  	reader_pubKey.setModulus(READER_KEY_MOD,(short) 0,(short) 128);
  	  	reader_pubKey.setExponent(READER_KEY_EXP, (short) 0, (short) 4);
  	  
    }
    
    public void generateCardKeys(APDU apdu) {
    	byte[] buffer = apdu.getBuffer();
    	keyPair = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_1024);
    	keyPair.genKeyPair();
    	
    	publicKey = (RSAPublicKey) keyPair.getPublic();
    	short pubKeyMod = publicKey.getModulus(CARD_KEY_MOD, (short)(0));
    	short pubKeyExp = publicKey.getExponent(CARD_KEY_EXP, (short)(0));
    	
    	privateKey = (RSAPrivateCrtKey) keyPair.getPrivate();
    	//not too sure whether we need this part or not since we are crating other methods to send exp and mod
//    	buffer[0] = (byte) pubKeyExp;
//        buffer[1] = (byte) pubKeyMod;
//        apdu.setOutgoingAndSend((short) 0, (short) 2);
    }
    

    public void sendCardPubKeyMod(APDU apdu){
    	byte[] buffer = apdu.getBuffer();
    	short pubKeyMod = publicKey.getModulus(CARD_KEY_MOD, (short)(0));
    	apdu.setOutgoing();
    	apdu.setOutgoingLength(pubKeyMod);
    	apdu.sendBytesLong(CARD_KEY_MOD,(short)0,pubKeyMod);
    }

    public void sendCardPubKeyExp(APDU apdu) {
    	byte[] buffer = apdu.getBuffer();
    	short pubKeyExp = publicKey.getExponent(CARD_KEY_EXP, (short)(0));
    	apdu.setOutgoing();
    	apdu.setOutgoingLength(pubKeyExp);
    	apdu.sendBytesLong(CARD_KEY_EXP,(short)0,pubKeyExp);    	
    }
    
    public short signMessage(byte[] message, short msgLen) {
    	  signature = Signature.getInstance(Signature.ALG_RSA_SHA256_PKCS1, false);
    	  signature.init(privateKey, Signature.MODE_SIGN);
    	  short sigLen = signature.sign(message, (short) 0, (byte) msgLen, SIGNED_MSG, (byte) 0);
    	  return sigLen;
    }
    
    public void signAndSend(APDU apdu, short msgLen) {
    	byte[] buffer = apdu.getBuffer();
    	short sigLen = signMessage(MSG, msgLen);
    	
    	//The signed message becomes the actual sent message
    	Util.arrayCopyNonAtomic(SIGNED_MSG, (short) 0, MSG, msgLen, sigLen);
    	
    	//Not too sure about the length here, because it is the length of the response data
    	apdu.setOutgoing();
    	//apdu.setOutgoingLength();
    	//apdu.sendBytesLong(MSG,(short)0,); 
    }
    
    public short receiveSigned(APDU apdu) {
    	byte[] buffer = apdu.getBuffer(0);
    	short bytesRead = 0;
    	short readOffset = 0;
    	short msgLen = 0;
    	short numBytes = (short) buffer[ISO7816.OFFSET_LC];
    	
    	
    	bytesRead = apdu.setIncomingAndReceive();
    	
    	while (bytesRead > 0) {
    		Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, MSG_AND_SIG, readOffset, bytesRead);
    		readOffset += bytesRead;
            bytesRead = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
    	}
    	
    	msgLen = (short) (numBytes - (short) 128);
    	
    	return msgLen;
    }
    
    public boolean verifyMessage(short msgLen) {
    	signature = Signature.getInstance(Signature.ALG_RSA_SHA256_PKCS1, false);
  	  	signature.init(reader_pubKey, Signature.MODE_VERIFY);
  	  	boolean verified = signature.verify(MSG_AND_SIG, (short) 0 , (byte) msgLen, MSG_AND_SIG, (byte) msgLen, (short) 128);
  	  	return verified;
    }
    
    
    
    
}