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
    public static final byte INS_CREDIT = (byte) 0x20;
    public static final byte INS_DEBIT = (byte) 0x30;
    public static final byte INS_GENERATE_CARD_KEYS = (byte) 0x40;
    public static final byte READER_PUBKEY_MOD = (byte) 0x50;
    public static final byte READER_PUBKEY_EXP = (byte) 0x51;
    public static final byte READER_PUBKEY = (byte) 0x52;
    public static final byte SEND_CARD_PUBKEY = (byte) 0x60;

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
    private static byte[] READER_KEY_MOD;
    private static byte[] READER_KEY_EXP;
    private static byte[] READER_KEY;

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
        keyPair = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_1024);
        keyPair.genKeyPair();
        publicKey = (RSAPublicKey) keyPair.getPublic();
        privateKey = (RSAPrivateCrtKey) keyPair.getPrivate();

        signature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
        verify = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
        signature.init(privateKey, Signature.MODE_SIGN);

        pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE); // Create User PIN

        byte iLen = bArray[bOffset]; // AID length
        bOffset = (short) (bOffset + iLen + 1);
        byte cLen = bArray[bOffset]; // info length
        bOffset = (short) (bOffset + cLen + 1);
        byte aLen = bArray[bOffset]; // applet data length

        pin.update(bArray, (short) (bOffset + 1), (byte) 0x04);

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

    private void unblockCard(APDU apdu) {
        if (pin.getTriesRemaining() != 0) {
            ISOException.throwIt(SW_UNBLOCK_NON_BLOCKED_CARD);
        }

        byte[] buffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();
        byte[] secret = { 'K', 'e', 'v', 'i', 'n' };

        byte unblock = Util.arrayCompare(buffer, (short) ISO7816.OFFSET_CDATA, secret, (short) 0, (short) 5);

        if (unblock != 0) {
            ISOException.throwIt(SW_VERIFICATION_FAILED);
        }

        pin.resetAndUnblock();
    }

    public void process(APDU apdu) throws ISOException {
        byte buf[] = apdu.getBuffer();

        if (this.selectingApplet())
            return;

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
                unblockCard(apdu);
                break;
            case INS_DEBIT:
                if (!pin.isValidated())
                    ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
                if (verifySignature(apdu) == true) debit(apdu);
                else ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                break;
            case INS_CREDIT:
                if (!pin.isValidated())
                    ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
                if (verifySignature(apdu) == true) credit(apdu);
                else ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                break;
            case INS_GET_BALANCE:
                if (!pin.isValidated())
                    ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
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
        apdu.setOutgoingAndSend((short) 0, (short) (num_participant.length + card_user_name.length));

    }

    private void getBalance(APDU apdu) {
        byte buffer[] = apdu.getBuffer();

        Util.setShort(buffer, (short) 0, card_amount);
        apdu.setOutgoingAndSend((short) 0, (short) 2);
    }

    private void credit(APDU apdu) {
        byte[] buf = apdu.getBuffer();

        short credit_amount = Util.getShort(buf, (short) ISO7816.OFFSET_CDATA);

        if (credit_amount < 0 || credit_amount > MAX_INPUT_AMOUNT)
            ISOException.throwIt(SW_INVALID_INPUT_CREDIT);

        if ((short) (card_amount + credit_amount) > MAX_BALANCE)
            ISOException.throwIt(SW_MAX_BALANCE);

        card_amount = (short) (card_amount + credit_amount);

        try {
            Util.setShort(buf, (short) 0, credit_amount);
            short signatureLength = signature.sign(buf, (short) 0, (short) 2, buf, (short) 2);
            apdu.setOutgoingAndSend((short) 0, (short) (2 + signatureLength));
        } catch (CryptoException c) {
            short reason = c.getReason();
            ISOException.throwIt(reason);
        }
    }

    private void debit(APDU apdu) {
        byte[] buf = apdu.getBuffer();

        short debit_amount = Util.getShort(buf, (short) ISO7816.OFFSET_CDATA);

        if (debit_amount < 0 || debit_amount > MAX_DEBIT_AMOUNT)
            ISOException.throwIt(SW_INVALID_INPUT_DEBIT);

        if (debit_amount > card_amount)
            ISOException.throwIt(SW_NEG_BALANCE);

        card_amount = (short) (card_amount - debit_amount);

        try {
            Util.setShort(buf, (short) 0, debit_amount);
            short signatureLength = signature.sign(buf, (short) 0, (short) 2, buf, (short) 2);
            apdu.setOutgoingAndSend((short) 0, (short) (2 + signatureLength));
        } catch (CryptoException c) {
            short reason = c.getReason();
            ISOException.throwIt(reason);
        }

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

        reader_pubKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024,
                false);
        try {
            reader_pubKey.setModulus(READER_KEY_MOD, (short) 0, (short) READER_KEY_MOD.length);
            reader_pubKey.setExponent(READER_KEY_EXP, (short) 0, (short) READER_KEY_EXP.length);
            verify.init(reader_pubKey, Signature.MODE_VERIFY);
        } catch (CryptoException c) {
            short reason = c.getReason();
            ISOException.throwIt(reason);
        }
    }

    public void sendCardPubKey(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short modLen = publicKey.getModulus(buffer, (short) 2);
        Util.setShort(buffer, (short) 0, modLen);
        short expLen = publicKey.getExponent(buffer, (short) (modLen + 4));
        Util.setShort(buffer, (short) (modLen + 2), expLen);
        apdu.setOutgoingAndSend((short) 0, (short) (4 + modLen + expLen));
    }

    public boolean verifySignature(APDU apdu){
        byte[] buf = apdu.getBuffer();

        short bytesRead = apdu.setIncomingAndReceive();
        try{
            boolean verified = verify.verify(buf, ISO7816.OFFSET_CDATA, (short) 2, buf, (short) (ISO7816.OFFSET_CDATA + 2), (short) (bytesRead - 2));
            if (verified) {
                return true;
            } else {
                return false;
            }
        
        } catch (CryptoException c) {
            short reason = c.getReason();
            ISOException.throwIt(reason);
        }
        return false;
    }

}
