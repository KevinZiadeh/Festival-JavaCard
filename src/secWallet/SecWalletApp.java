package secWallet;

import javacard.framework.APDU;
import javacard.framework.Applet; // https://docs.oracle.com/javacard/3.0.5/api/javacard/framework/Applet.html
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN; // https://docs.oracle.com/javacard/3.0.5/api/javacard/framework/OwnerPIN.html
import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class SecWalletApp extends Applet {
    public static final byte CLA_MONAPPLET = (byte) 0xB0;

    /* INSTRUCTIONS */
    public static final byte INS_GET_INFO = (byte) 0x00;
    public static final byte INS_VERIFY_PIN = (byte) 0x01;
    public static final byte INS_UNBLOCK_CARD = (byte) 0x02;
    public static final byte INS_GET_BALANCE = (byte) 0x10;
    public static final byte INS_CREDIT = (byte)0x20;
    public static final byte INS_DEBIT = (byte)0x30;
    public static final byte INS_GENERATE_CARD_KEYS = (byte)0x40;
    public static final byte READER_PUBKEY_MOD = (byte)0x50;
    public static final byte READER_PUBKEY_EXP = (byte)0x51;
    public static final byte READER_PUBKEY = (byte)0x52;
    public static final byte SEND_CARD_PUBKEY = (byte)0x60; 
    public static final byte RECEIVE_VERIFY_SIGNED_MSG = (byte)0x70;
    public static final byte SIGN_SEND_MSG = (byte)0x80;
    

    /* ATTRIBUTES */
    OwnerPIN pin;
    private Signature signature;
    private Signature verify;
    private KeyPair keyPair;
    private RSAPrivateCrtKey privateKey;
    private RSAPublicKey publicKey;
    private RSAPublicKey reader_pubKey;

    
    short card_amount;
    private static byte[] card_user_name;
    private static byte[] num_participant;
    
    /* SIGNATURE ATTRIBUTES */
    private short msgLen;
    private static byte[] READER_KEY_MOD;
    private static byte[] READER_KEY_EXP;
    private static byte[] READER_KEY;
    private static byte[] CARD_KEY_MOD; 
    private static byte[] CARD_KEY_EXP;
    private static byte[] MSG_TO_SEND; // = {72,101,108,108,111};
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
    public static final short SW_PIN_TRY_LIMIT_REACHED = 0x6302;
    public static final short SW_UNBLOCK_NON_BLOCKED_CARD = 0x6303;
    public static final short SW_MAX_BALANCE = 0x6400;
    public static final short SW_NEG_BALANCE = 0x6401;
    public static final short SW_INVALID_INPUT_CREDIT = 0x6402;
    public static final short SW_INVALID_INPUT_DEBIT = 0x6403;


    /* Constructor */
    private SecWalletApp(byte bArray[], short bOffset, byte bLength) {
    	 SIGNED_MSG = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_DESELECT);
    	 MSG_AND_SIG = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_DESELECT);
//    	 String msg = "Testing send and sign card";
    	 MSG = new byte[256];  
         msgLen = 0;

        keyPair = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_1024);
        keyPair.genKeyPair();
        publicKey = (RSAPublicKey) keyPair.getPublic();
    	privateKey = (RSAPrivateCrtKey) keyPair.getPrivate();

        signature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
        verify = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
//        signature.init(privateKey, Signature.MODE_SIGN);
    	
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
        return true;
    }

    public void deselect() {
        pin.reset();
    }
    
    private void verifyPin(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte byteRead = (byte) (apdu.setIncomingAndReceive());

        if (pin.getTriesRemaining() == 0) {
            ISOException.throwIt(SW_PIN_TRY_LIMIT_REACHED);
        }

        if (pin.check(buffer, ISO7816.OFFSET_CDATA, byteRead) == false) {
            ISOException.throwIt(SW_VERIFICATION_FAILED);
        }
    } 

    private void unblockCard() {
        if (pin.getTriesRemaining() != 0) {
            ISOException.throwIt(SW_UNBLOCK_NON_BLOCKED_CARD);
        }

        pin.resetAndUnblock();
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
            case INS_UNBLOCK_CARD:
                unblockCard();
                break;
            case INS_DEBIT:
            	if (!pin.isValidated()) ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
            	msgLen = receiveSigned(apdu);
//            	if (verifyMessage(msgLen) == true) {
            		debit(apdu, msgLen);
            		break;		
//            	} // should throw some kind of error here 
            case INS_CREDIT:
            	if (!pin.isValidated()) ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
//            	msgLen = receiveSigned(apdu);
//            	if (verifyMessage(msgLen) == true) {
            		credit(apdu);
            		break;		
//            	}
            case INS_GET_BALANCE:
                if (!pin.isValidated()) ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
                getBalance(apdu);
                break;
            case READER_PUBKEY_MOD:
            	getReaderKeyMod(apdu);
            	break;
            case READER_PUBKEY_EXP:
            	getReaderKeyExp(apdu);
            	break;
            case READER_PUBKEY: 
            	constructReaderKey(apdu);
            	break;
            case SEND_CARD_PUBKEY:
            	sendCardPubKey(apdu);
            	break;
            case RECEIVE_VERIFY_SIGNED_MSG:
            	receiveAndVerify(apdu);
            	break;
            case SIGN_SEND_MSG:
            	MSG_TO_SEND = new byte[] {72,101,108,108,111};
            	signAndSend(apdu, MSG_TO_SEND);
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

    }

    private void getBalance(APDU apdu) {
        byte buffer[] = apdu.getBuffer();
        
        Util.setShort(buffer, (short) 0, card_amount);
        apdu.setOutgoingAndSend((short) 0, (short) 2);      
    }
    
    private void credit(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        byte numBytes = buf[ISO7816.OFFSET_LC];
        byte read = (byte)apdu.setIncomingAndReceive();
        
        if (numBytes < 1 || numBytes > 2 || read < 1 || read > 2) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
       
        short input_amount = Util.getShort(buf, (short) ISO7816.OFFSET_CDATA);
                
        if (input_amount < 0 || input_amount > MAX_INPUT_AMOUNT) ISOException.throwIt(SW_INVALID_INPUT_CREDIT); 
                
        if ((short) (card_amount + input_amount) > MAX_BALANCE) ISOException.throwIt(SW_MAX_BALANCE); 
        
        card_amount = (short) (card_amount + input_amount);
//        byte[] str = {'O', 'K'};
//        Util.arrayCopyNonAtomic(str, (short) 0, buf, (short) 0, (short)2);
//        apdu.setOutgoingAndSend((short) 0, (short) 2);

        //Not too sure we want to do signing when adding money 
        //also where is the verification of the signature supposed to happen, maybe at the terminal level or vice versa
        //either terminal(reader or client) signs its transaction and the card verifies the signature before taking money in
        //or out
    } 
    
    private void debit(APDU apdu, short msgLen) {
        byte[] buf = apdu.getBuffer();
        byte numBytes = buf[ISO7816.OFFSET_LC];
        byte read = (byte)apdu.setIncomingAndReceive();
        
        if (numBytes < 1 || numBytes > 2 || read < 1 || read > 2) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
       
        short debit_amount = Util.getShort(buf, (short) ISO7816.OFFSET_CDATA);
                
        if (debit_amount < 0 || debit_amount > MAX_DEBIT_AMOUNT) ISOException.throwIt(SW_INVALID_INPUT_DEBIT); 
        
        if (debit_amount > card_amount) ISOException.throwIt(SW_NEG_BALANCE); 
        
        card_amount = (short) (card_amount - debit_amount);
//        byte[] str = {'O', 'K'};
//        Util.arrayCopyNonAtomic(str, (short) 0, buf, (short) 0, (short)2);
//        apdu.setOutgoingAndSend((short) 0, (short) 2);
                
        short signatureLength = signature.sign(buf, ISO7816.OFFSET_CDATA, msgLen, buf, (short) 0);
        
        //send the signature back to the terminal 
        apdu.setOutgoing();
        apdu.setOutgoingLength(signatureLength);
        apdu.sendBytesLong(buf, (short) 0, signatureLength);
    }
    
    public void getReaderKeyMod(APDU apdu) {
    	byte[] buffer = apdu.getBuffer();
        short bytesRead = apdu.setIncomingAndReceive();
        READER_KEY_MOD = new byte[128]; 
        Util.arrayCopyNonAtomic(buffer, (short) ISO7816.OFFSET_CDATA, READER_KEY_MOD, (short) 0, bytesRead);
    }
    
    public void getReaderKeyExp(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short bytesRead = apdu.setIncomingAndReceive();
    	READER_KEY_EXP = new byte[128]; 
        Util.arrayCopyNonAtomic(buffer, (short) ISO7816.OFFSET_CDATA, READER_KEY_EXP, (short) 0, bytesRead);
    }
    
    public void constructReaderKey(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

  	  	reader_pubKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024, false);
  	  	try {
  	  		reader_pubKey.setModulus(READER_KEY_MOD,(short) 0,(short) READER_KEY_MOD.length);
  	  		reader_pubKey.setExponent(READER_KEY_EXP, (short) 0, (short) READER_KEY_EXP.length);
  	  	} catch(CryptoException c) {
	  	  	short reason = c.getReason();
	  		ISOException.throwIt(reason);
  	  	}
    }
    
    public void sendCardPubKey(APDU apdu){
    	byte[] buffer = apdu.getBuffer();
    	short modLen = publicKey.getModulus(buffer, (short) 2);
        Util.setShort(buffer, (short) 0, modLen);
        short expLen = publicKey.getExponent(buffer, (short) (modLen + 4));
        Util.setShort(buffer, (short) (modLen + 2), expLen);
        apdu.setOutgoingAndSend((short) 0, (short)(4 + modLen + expLen));
    }
    
    public short signMessage(byte[] message, short msgLen) {
    	  signature.init(privateKey, Signature.MODE_SIGN);
    	  short sigLen = signature.sign(message, (short) 0, (byte) msgLen, SIGNED_MSG, (byte) 0);
    	  return sigLen;
    }
    
    public void signAndSend(APDU apdu, byte[] message) {
    	byte[] buffer = apdu.getBuffer();
    	short msgLen = (short) message.length;
    	
    	
    	short sigLen = signMessage(message, msgLen);

    	Util.arrayCopyNonAtomic(MSG_TO_SEND, (short) 0, MSG, (short)0, msgLen);
    	Util.arrayCopyNonAtomic(SIGNED_MSG, (short) 0, MSG, (short)msgLen, sigLen);

    	apdu.setOutgoing();
    	apdu.setOutgoingLength((short)(msgLen + sigLen));
    	apdu.sendBytesLong(MSG,(short)0,(short)(msgLen + sigLen)); 
    }
    
    public short receiveSigned(APDU apdu) {
    	byte[] buffer = apdu.getBuffer();
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
    
    public boolean verifySignature(short msgLen) {
  	  	signature.init(reader_pubKey, Signature.MODE_VERIFY);
  	  	boolean verified = signature.verify(MSG_AND_SIG, (short) 0 , (byte) msgLen, MSG_AND_SIG, (byte) msgLen, (short) 128);
  	  	return verified;
    }
    
    public void receiveAndVerify(APDU apdu) {
    	byte[] buf = apdu.getBuffer();
    	msgLen = receiveSigned(apdu);
    	if (verifySignature(msgLen) == true) {
          byte[] str = {'O', 'K'};
          Util.arrayCopyNonAtomic(str, (short) 0, buf, (short) 0, (short)2);
          apdu.setOutgoingAndSend((short) 0, (short) 2);               
    	} else {
          byte[] str = {'N', 'O'};
          Util.arrayCopyNonAtomic(str, (short) 0, buf, (short) 0, (short)2);
          apdu.setOutgoingAndSend((short) 0, (short) 2);
                  
    	}
    }
    
    
}
