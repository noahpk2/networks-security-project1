import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.io.BufferedOutputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

public class keyGeneration {
    //need to generate 2 pairs of RSA public and private keys for X and Y
    public keyGeneration() {
        int BLOCK_SIZE = 16*1024;

        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
        //Generate a pair of keys
        SecureRandom random = new SecureRandom();
        KeyPairGenerator generator = null;
        try {
            generator = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        generator.initialize(128, random);
        KeyPair pair = generator.generateKeyPair();
        KeyPair pair2 = generator.generateKeyPair();
        Key KxPublic = pair.getPublic();
        Key KxPrivate = pair.getPrivate();
        Key KyPublic = pair2.getPublic();
        Key KyPrivate = pair2.getPrivate();

        //get the parameters of the keys: modulus and exponent
        KeyFactory factory = null;
        try {
            factory = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        RSAPublicKeySpec KxPubSpec;
        try {
            KxPubSpec = factory.getKeySpec(KxPublic,
                    RSAPublicKeySpec.class);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
        RSAPrivateKeySpec KxPrivSpec;
        try {
            KxPrivSpec = factory.getKeySpec(KxPrivate,
                    RSAPrivateKeySpec.class);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
        RSAPublicKeySpec KyPubSpec;
        try {
            KyPubSpec = factory.getKeySpec(KyPublic,
                    RSAPublicKeySpec.class);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
        RSAPrivateKeySpec KyPrivSpec;
        try {
            KyPrivSpec = factory.getKeySpec(KyPrivate,
                    RSAPrivateKeySpec.class);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
        try {
            //save the parameters of the keys to the files
            RSAConfidentiality.saveToFile("XPublic.key", KxPubSpec.getModulus(),
                    KxPubSpec.getPublicExponent());
            RSAConfidentiality.saveToFile("XPrivate.key", KxPrivSpec.getModulus(),
                    KxPrivSpec.getPrivateExponent());
            RSAConfidentiality.saveToFile("YPublic.key", KyPubSpec.getModulus(),
                    KyPubSpec.getPublicExponent());
            RSAConfidentiality.saveToFile("YPrivate.key", KyPrivSpec.getModulus(),
                    KyPrivSpec.getPrivateExponent());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        /*int BUFFER_SIZE = 16;
        BufferedOutputStream symKeyFile = null;
        try {
            symKeyFile = new BufferedOutputStream(new FileOutputStream("symmetric.key"), BUFFER_SIZE);
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }
        byte[] buffer = new byte[BUFFER_SIZE];
        symKeyFile.read(buffer, 0, BUFFER_SIZE);
        try {
            symKeyFile.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
            }*/

    }
}
