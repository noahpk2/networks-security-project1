package Sender;

import java.io.*;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.PrivateKey;


public class Sender {
    /*
     *
     */
    public static void main(String[] args) {

        try{
            
            PrivateKey privXkey = readPrivKeyFromFile("project01/KeyGen/XPrivate.key");
            System.out.println("privXkey:read");
            SecretKey symKey = readSymmetricKeyFromFile("project01/KeyGen/symmetric.key");
            encryptMessage(privXkey, symKey);
        }
        catch(Exception e){
            System.out.println("Error: " + e);
        }
    }

    public static SecretKey readSymmetricKeyFromFile(String keyFileName) throws IOException {
        byte[] keyBytes = Files.readAllBytes(Paths.get(keyFileName));
        return new SecretKeySpec(keyBytes, "AES");
    }
    
    private static void encryptMessage(PrivateKey privXkey, SecretKey symKey) {
        Scanner sc = new Scanner(System.in);
        System.out.println("Enter the name of the file containing the message to be encrypted(file must be in the same directory, or use full path): ");
        File message = null;

        while (message == null)
        {
            try {
                message = new File(sc.nextLine());
            } catch (Exception e) {
                System.out.println("Error: " + e);
                sc.close();
                return;
            }
        }

        int chunkSize = 16*1024;  // 16KB
        byte[] messageBytes = new byte[chunkSize];

        try(BufferedInputStream bis = new BufferedInputStream(new FileInputStream(message))) {

            int bytesRead = 0;

            while((bytesRead = bis.read(messageBytes,0,messageBytes.length)) != -1) {
                System.out.println("Read " + bytesRead + " bytes");
            }

            System.out.println("Total bytes read: " + bytesRead);
            System.out.println("Message read successfully");

        } catch (Exception e) {
            System.out.println("Error: " + e);
            sc.close();
            return;
        }



        // calculate the SHA256 hash of the entire message
        byte[] hash = null;
        try{
            MessageDigest mDigest = MessageDigest.getInstance("SHA-256");
            hash = mDigest.digest(messageBytes);
        }
        catch(Exception e){
            System.out.println("Error: " + e);
            sc.close();
            return;
        }


        // display the hash in hexadecimal bytes
        System.out.println("SHA256(M) = " + byteToHex(hash));

        // display  a prompt to the user : "do you want to invert the first byte in SHA256(M)? (y/n)"
        // if the user enters "y", invert the first byte in SHA256(M) and display the new hash
        System.out.println("Do you want to invert the first byte in SHA256(M)? (y/n)");
        String response = sc.nextLine();
        if (response.equals("y")||response.equals("Y")||response.equals("yes")||response.equals("Yes")) {
            hash[0] = (byte) ~hash[0]; // invert the first byte in SHA256(M)
            System.out.println("SHA256(M), first byte inverted = " + byteToHex(hash));
        }
        sc.close();

        //save the hash to a file called "message.dd" and display SHA256(M) in hexadecimal bytes
        File hashFile = new File("message.dd");
        try (BufferedOutputStream buf = new BufferedOutputStream(new FileOutputStream(hashFile))) {
            buf.write(hash);
            System.out.println("SHA256(M) written to message.dd\n");
            System.out.println("SHA256(M) = " + byteToHex(hash));
            buf.close();

        } catch (Exception e) {
            System.out.println("Error: " + e);
            sc.close();
            return;
        }


        // (RSA-En Kx– (SHA256 (M)) || M)
        
        // Calculate RSA encryption of the hash using the private key of the sender (Kx-), concatenate the resulting ciphertext with M, and save the resulting ciphertext to a file called "message.ds"
       
        try(BufferedInputStream bis = new BufferedInputStream(new FileInputStream(message));
            BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream("message.ds-msg", true))) {

            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, privXkey);
            byte[] encryptedBytes = cipher.doFinal(hash);

            // Write the encrypted hash to the file
            int hashLength = encryptedBytes.length;
            System.out.println("hashLength: " + hashLength);
            bos.write(encryptedBytes);

            //display the encrypted hash in hexadecimal bytes
            System.out.println("RSA-En Kx- (SHA256 (M)) = " + byteToHex(encryptedBytes));

            // Now, append the original message to the file
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = bis.read(buffer)) != -1) {
                bos.write(buffer, 0, bytesRead);
            }
        }

        catch(Exception e){
            System.out.println("Error: " + e);
            e.printStackTrace();
            return;
        }

        //AES encryption of the resulting file using the symmetric key
        // If the length of the last block is less than that multiple of 16 bytes, it needs to be placed in a byte array whose array size is the length of the last piece before being encrypted.


        try (BufferedInputStream bis = new BufferedInputStream(new FileInputStream("message.ds-msg"));
            BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream("message.aescipher"))) {

            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, symKey);

            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = bis.read(buffer)) != -1) {
                byte[] output = cipher.update(buffer, 0, bytesRead);
                if (output != null) {
                    bos.write(output);
                }
            }

            byte[] output = cipher.doFinal();
            if (output != null) {
                bos.write(output);
            }
        } catch (Exception e) {
            System.out.println("Error: " + e);
            e.printStackTrace();
            return;
        }
        
        

        

        
        

        

    }
    public static PrivateKey readPrivKeyFromFile(String keyFileName)
            throws IOException {
        InputStream in =
                new FileInputStream(keyFileName);
        ObjectInputStream oin =
                new ObjectInputStream(new BufferedInputStream(in));
        try {
            BigInteger m = (BigInteger) oin.readObject();
            BigInteger e = (BigInteger) oin.readObject();

            //System.out.println("Read from " + keyFileName + ": modulus = " +
            //        m.toString() + ", exponent = " + e.toString() + "\n");



            RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(m, e);
            //System.out.println("keySpec: " + keySpec.toString());
            KeyFactory factory = KeyFactory.getInstance("RSA");
            //System.out.println("factory: " + factory.toString());

            PrivateKey key = factory.generatePrivate(keySpec);
            //System.out.println("key: " + key.toString());

            return key;

        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("Spurious serialisation error", e);
        } finally {
            System.out.println("Generated Keys\n");
            oin.close();
        }
    }

    public static String byteToHex(byte[] hash){
        StringBuilder hexString = new StringBuilder();

        for (byte b : hash){
            String hex = Integer.toHexString(0xff & b);
            if(hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }

        return hexString.toString();
    }

}
