package Receiver;
import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;




public class Receiver {

    public static void main(String[] args) {
        decryptMessage();
    }
    
    public static void decryptMessage() {
    /*
in the receiver’s program in the directory “Receiver”, using AES and RSA Decryptions to get SHA256 (M) and M, compare
SHA256(M) with the locally calculated SHA256 hash of M, report hashing error if any, and then save M to a file.
*/

        PublicKey pubXKey = null;
        SecretKey symKey = null;
        File encryptedMessage = null;
/*
1 To test this program, the corresponding key files need to be copied here from the directory “KeyGen”, and the file
“message.aescipher” needs to be copied here from the directory “Sender”.
*/
//2 Read the information on the keys to be used in this program from the key files and generate Kx+ and Kxy.

        try{
            pubXKey = readPubKeyFromFile("project01/KeyGen/XPublic.key");
            symKey = readSymmetricKeyFromFile("project01/KeyGen/symmetric.key");
            encryptedMessage = new File("message.aescipher");
        }
        catch(Exception e){
            System.out.println("Error: " + e);
            e.printStackTrace();
            return;
        }

/*
3 Display a prompt “Input the name of the message file:” and take a user input from the keyboard. The
resulting message M will be saved to this file at the end of this program.
*/
        Scanner sc  = new Scanner(System.in);
        System.out.println("Input the name of the (output) message file: ");
        String messageFileName = sc.nextLine();

/*
4 Read the ciphertext, C, from the file “message.aescipher” block by block, where each block needs to be a multiple of 16
bytes long. (Hint: if the length of the last block is less than that multiple of 16 bytes, it needs to be placed in a byte array
whose array size is the length of the last piece before being decrypted.) Calculate the AES Decryption of C using Kxy
block by block to get RSA-En Kx - (SHA256 (M)) || M, and save the resulting pieces into a file named “message.ds-msg”.
*/
        //byte[] encryptedBytes = null;

        int blockSize = 16*1024;
        

        try(BufferedInputStream bis = new BufferedInputStream(new FileInputStream(encryptedMessage));
            BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream("message.ds-msg"))){

            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, symKey);
            byte[] encryptedBytes = new byte[blockSize];
            int bytesRead = 0;
            while ((bytesRead = bis.read(encryptedBytes, 0, encryptedBytes.length)) != -1) {
                System.out.println("Read " + bytesRead + " bytes");
                byte[] output = cipher.update(encryptedBytes, 0, bytesRead);
                bos.write(output);
            }
            
            byte[] output = cipher.doFinal();
            if (output != null) {
                bos.write(output);
            }


        }
        catch(Exception e){
            System.out.println("Error: " + e);
            e.printStackTrace();
            return;
        }

        //TEST CODE: KEY COMPARISON
        // try{
        // String test = "test";
        // byte[] sampledata = test.getBytes(); 
        // PrivateKey privXkey = Sender.readPrivKeyFromFile("project01/KeyGen/XPrivate.key");
        // Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        // cipher.init(Cipher.ENCRYPT_MODE, privXkey);
        // byte[] encryptedData = cipher.doFinal(sampledata);

        // cipher.init(Cipher.DECRYPT_MODE, pubXKey);
        // byte[] decryptedData = cipher.doFinal(encryptedData);
        // System.out.println("TEST: " + new String(decryptedData));
        


        // }
        // catch(Exception e){
        //     System.out.println("Error: " + e);
        //     e.printStackTrace();
        //     return;
        // }


  /*
5 If using "RSA/ECB/PKCS1Padding", read the first 128 bytes from the file “message.ds-msg” to get the digital signature
RSA-En Kx- (SHA256 (M)), and copy the message M, i.e., the leftover bytes in the file “message.ds-msg”, to a file whose
name is specified in Step 3. (Why 128 bytes? Why is the leftover M?) Calculate the RSA Decryption of this digital
signature using Kx+ to get the digital digest SHA256(M), SAVE this digital digest into a file named “message.dd”, and
DISPLAY it in Hexadecimal bytes.
*/      byte[] digitalSignature = new byte[128];
        byte[] decryptedBytes = null;

        try(BufferedInputStream bis = new BufferedInputStream(new FileInputStream("message.ds-msg"));
            BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(messageFileName));
            BufferedOutputStream bosDigest = new BufferedOutputStream(new FileOutputStream("message.dd"))) {
            
            //Why 128? the RSA encryption of the SHA256 hash is 128 bytes long when using a 1024 bit key. 
            //The leftover is M because we concatenated the hash and the message together in the sender program.
            bis.read(digitalSignature);
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, pubXKey);
            decryptedBytes = cipher.doFinal(digitalSignature);

            bosDigest.write(decryptedBytes);
            System.out.println("SHA256(M) obtained from ciphertext: " + byteToHex(decryptedBytes));
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


    /*
6 Read the message M from the file whose name is specified in Step 3 piece by piece, where each piece is recommended to
be a small multiple of 1024 bytes, calculate the SHA256 hash value (digital digest) of the entire message M, DISPLAY it
in Hexadecimal bytes, compare it with the digital digest obtained in Step 5, display whether the digital digest passes the
authentication check.
 */
        
        try (BufferedInputStream bis = new BufferedInputStream(new FileInputStream(messageFileName))) {

            MessageDigest md = MessageDigest.getInstance("SHA-256");

            byte[] buffer = new byte[1024*16];
            int bytesRead=0;
            while ((bytesRead = bis.read(buffer)) != -1) {
                
        
            }
            

            byte[] messageHash = md.digest(buffer);
            String messageHashHex = byteToHex(messageHash);

            System.out.println("SHA256(M) obtained from decrypted message: " + messageHashHex);


            //compare the two hashes
            
            String digitalDigestHex = byteToHex(decryptedBytes);

            System.out.println(decryptedBytes.length);
            System.out.println(messageHash.length);

            if (messageHashHex.equals(digitalDigestHex)) {
                System.out.println("The digital digest passes the authentication check.");
            } else {
                // check if the first byte is inverted
                decryptedBytes[0] = (byte) ~decryptedBytes[0];
                digitalDigestHex = byteToHex(decryptedBytes);
                if (messageHashHex.equals(digitalDigestHex)) {
                    System.out.println("The digital digest passes the authentication check (first byte was inverted).");

                } else{
                System.out.println("The digital digest does not pass the authentication check.");
                }
            }

            } catch (Exception e) {
                System.out.println("Error: " + e);
                e.printStackTrace();
                return;
            }

}


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


    public static String byteToHex(byte[] hash){
        StringBuilder hexString = new StringBuilder();

        for (byte b : hash){
            String hex = Integer.toHexString(0xff & b);
            if(hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }

        return hexString.toString();
    }


    public static SecretKey readSymmetricKeyFromFile(String keyFileName) throws IOException {
        BufferedInputStream keyFile = new BufferedInputStream(new FileInputStream(keyFileName));
        byte[] keyBytes = new byte[keyFile.available()];
        keyFile.read(keyBytes);
        keyFile.close();
        return new SecretKeySpec(keyBytes, "AES");
    }



}
