import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;


public class keyGeneration {
    //need to generate 2 pairs of RSA public and private keys for X and Y
    public keyGeneration() throws Exception {

        int BLOCK_SIZE = 16*1024;
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");


        //Generate a pair of keys
        SecureRandom random = new SecureRandom();
        KeyPairGenerator generator = null;
        generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(128, random);
        KeyPair pair = generator.generateKeyPair();
        KeyPair pair2 = generator.generateKeyPair();
        Key KxPublic = pair.getPublic();
        Key KxPrivate = pair.getPrivate();
        Key KyPublic = pair2.getPublic();
        Key KyPrivate = pair2.getPrivate();

        //get the parameters of the keys: modulus and exponent
        KeyFactory factory = KeyFactory.getInstance("RSA");

        RSAPublicKeySpec KxPubSpec = factory.getKeySpec(KxPublic, RSAPublicKeySpec.class);
        RSAPrivateKeySpec KxPrivSpec = factory.getKeySpec(KxPrivate, RSAPrivateKeySpec.class);
        RSAPublicKeySpec KyPubSpec = factory.getKeySpec(KyPublic, RSAPublicKeySpec.class);
        RSAPrivateKeySpec KyPrivSpec = factory.getKeySpec(KyPrivate, RSAPrivateKeySpec.class);

        //save the parameters of the keys to the files
        RSAConfidentiality.saveToFile("XPublic.key", KxPubSpec.getModulus(), KxPubSpec.getPublicExponent());
        RSAConfidentiality.saveToFile("XPrivate.key", KxPrivSpec.getModulus(), KxPrivSpec.getPrivateExponent());
        RSAConfidentiality.saveToFile("YPublic.key", KyPubSpec.getModulus(), KyPubSpec.getPublicExponent());
        RSAConfidentiality.saveToFile("YPrivate.key", KyPrivSpec.getModulus(), KyPrivSpec.getPrivateExponent());


        PublicKey pubXKey2 = readPubKeyFromFile("XPublic.key");
        PrivateKey privXKey2 = readPrivKeyFromFile("XPrivate.key");
        PublicKey pubYKey2 = readPubKeyFromFile("YPublic.key");
        PrivateKey privYKey2 = readPrivKeyFromFile("YPrivate.key");

        //encrypt & decrypt using the keys from the files
        byte[] input2 = "Hello World! (using the keys from files)".getBytes();
        cipher.init(Cipher.ENCRYPT_MODE, pubXKey2, random);
        byte[] cipherText2 = cipher.doFinal(input2);
        System.out.println("cipherText2: (" + cipherText2.length + "bytes)");
        for (int i=0, j=0; i<cipherText2.length; i++, j++) {
            System.out.format("%2X ", cipherText2[i]) ;
            if (j >= 15) {
                System.out.println("");
                j=-1;
            }
        }


    }
    public static void saveToFile(String fileName, BigInteger mod, BigInteger exp) throws IOException {
        System.out.println("Write to " + fileName + ": modulus = " +
                mod.toString() + ", exponent = " + exp.toString() + "\n");
        ObjectOutputStream oout = new ObjectOutputStream(
                new BufferedOutputStream(new FileOutputStream(fileName)));
        try {
            oout.writeObject(mod);
            oout.writeObject(exp);
        } catch (Exception e) {
            throw new IOException("Unexpected error", e);
        } finally {
            oout.close();
        }
    }
    //read key parameters from a file and generate the public key
    public static PublicKey readPubKeyFromFile(String keyFileName)
            throws IOException {
        InputStream in =
                RSAConfidentiality.class.getResourceAsStream(keyFileName);
        ObjectInputStream oin =
                new ObjectInputStream(new BufferedInputStream(in));
        try {
            BigInteger m = (BigInteger) oin.readObject();
            BigInteger e = (BigInteger) oin.readObject();
            System.out.println("Read from " + keyFileName + ": modulus = " +
                    m.toString() + ", exponent = " + e.toString() + "\n");
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(m, e);
            KeyFactory factory = KeyFactory.getInstance("RSA");
            PublicKey key = factory.generatePublic(keySpec);
            return key;
        } catch (Exception e) {
            throw new RuntimeException("Spurious serialisation error", e);
        } finally {
            oin.close();
        }
    }
    //read key parameters from a file and generate the private key
    public static PrivateKey readPrivKeyFromFile(String keyFileName)
            throws IOException {
        InputStream in =
                RSAConfidentiality.class.getResourceAsStream(keyFileName);
        ObjectInputStream oin =
                new ObjectInputStream(new BufferedInputStream(in));
        try {
            BigInteger m = (BigInteger) oin.readObject();
            BigInteger e = (BigInteger) oin.readObject();
            System.out.println("Read from " + keyFileName + ": modulus = " +
                    m.toString() + ", exponent = " + e.toString() + "\n");
            RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(m, e);
            KeyFactory factory = KeyFactory.getInstance("RSA");
            PrivateKey key = factory.generatePrivate(keySpec);
            return key;
        } catch (Exception e) {
            throw new RuntimeException("Spurious serialisation error", e);
        } finally {
            oin.close();
        }
    }
}
