package KeyGen;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Scanner;


public class keyGeneration {
    //need to generate 2 pairs of RSA public and private keys for X and Y
    public static void Generate() throws Exception {

        //Generate key pairs for X and Y - even though we're only using x for this particular encryption.
        SecureRandom random = new SecureRandom();
        KeyPairGenerator generator = null;
        generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024, random);
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
        //change name to your id for terminal 
        saveToFile("project01/KeyGen/XPublic.key", KxPubSpec.getModulus(), KxPubSpec.getPublicExponent());
        saveToFile("project01/KeyGen/XPrivate.key", KxPrivSpec.getModulus(), KxPrivSpec.getPrivateExponent());
        saveToFile("project01/KeyGen/YPublic.key", KyPubSpec.getModulus(), KyPubSpec.getPublicExponent());
        saveToFile("project01/KeyGen/YPrivate.key", KyPrivSpec.getModulus(), KyPrivSpec.getPrivateExponent());


    }

    public static void saveToFile(String fileName, BigInteger mod, BigInteger exp) throws IOException {
        //System.out.println("Write to " + fileName + ": modulus = " +
        //       mod.toString() + ", exponent = " + exp.toString() + "\n");

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
