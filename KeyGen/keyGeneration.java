package KeyGen;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Scanner;


public class keyGeneration {
    //need to generate 2 pairs of RSA public and private keys for X and Y
    public static void Generate() throws Exception {

        //int BLOCK_SIZE = 16*1024; // 16KB - AES block size - didn't end up using this here
        
        //Generate key pairs for X and Y - even though we're only using x for this particular encryption.
        SecureRandom random = new SecureRandom();
        KeyPairGenerator generator = null;
        generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, random);
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
        saveToFile("project01/KeyGen/XPublic.key", KxPubSpec.getModulus(), KxPubSpec.getPublicExponent());
        saveToFile("project01/KeyGen/XPrivate.key", KxPrivSpec.getModulus(), KxPrivSpec.getPrivateExponent());
        saveToFile("project01/KeyGen/YPublic.key", KyPubSpec.getModulus(), KyPubSpec.getPublicExponent());
        saveToFile("project01/KeyGen/YPrivate.key", KyPrivSpec.getModulus(), KyPrivSpec.getPrivateExponent());



        /* // read keys from files - not needed for this class
        PublicKey pubXKey2 = readPubKeyFromFile("XPublic.key");
        PrivateKey privXKey2 = readPrivKeyFromFile("XPrivate.key");
        PublicKey pubYKey2 = readPubKeyFromFile("YPublic.key");
        PrivateKey privYKey2 = readPrivKeyFromFile("YPrivate.key"); */

        /* //encrypt & decrypt using the keys from the files (is this a test?)
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
        } */
     

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
                new FileInputStream(keyFileName);

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
            System.out.println("Error: " + e);
            e.printStackTrace();
            throw new RuntimeException("Spurious serialisation error:", e);
            
        } finally {
            oin.close();
        }
    }

    
    //read key parameters from a file and generate the private key
    public static PrivateKey readPrivKeyFromFile(String keyFileName)
            throws IOException {
        InputStream in =
                new FileInputStream(keyFileName);
        ObjectInputStream oin =
                new ObjectInputStream(new BufferedInputStream(in));
        try {
            BigInteger m = (BigInteger) oin.readObject();
            BigInteger e = (BigInteger) oin.readObject();

            System.out.println("Read from " + keyFileName + ": modulus = " +
                    m.toString() + ", exponent = " + e.toString() + "\n");
            

            
            RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(m, e);
            System.out.println("keySpec: " + keySpec.toString());
            KeyFactory factory = KeyFactory.getInstance("RSA");
            System.out.println("factory: " + factory.toString());

            PrivateKey key = factory.generatePrivate(keySpec);
            System.out.println("key: " + key.toString());

            return key;

        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("Spurious serialisation error", e);
        } finally {
            oin.close();
        }
    }

   public static void main(String[] args){
        Scanner sc = new Scanner(System.in);
        System.out.println(" Enter a 16 Character Symmetric Key: ");
        String key = sc.nextLine();
        if(key.length() != 16)
        {
            System.out.println("Invalid Key Length");
        }
        else{
            try{
                Generate();
                BufferedOutputStream symKeyFile = new BufferedOutputStream(new FileOutputStream("project01/KeyGen/symmetric.key"));
                byte[] symKey = key.getBytes("UTF-8");
                symKeyFile.write(symKey, 0, symKey.length);

                // Truncate or pad the key if it is more than 16 bytes. Since UTF-8 is used, each character can be 1-4 bytes.
                // AES only supports 16 byte keys, so we need to truncate or pad the key to 16 bytes.
                if (symKey.length > 16) {
                    symKey = Arrays.copyOf(symKey, 16); // Truncate to 16 bytes
                } else if (symKey.length < 16) {
                    byte[] temp = new byte[16];
                    System.arraycopy(symKey, 0, temp, 0, symKey.length);
                    symKey = temp; // Pad with zeros
                }



                symKeyFile.close();
            }
            catch(Exception e){
                System.out.println("Error Generating Keys:");
                System.out.println(e);
            }
        }
        sc.close();

    }
   
}
