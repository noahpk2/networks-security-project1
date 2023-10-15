package Sender;

import KeyGen.keyGeneration;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.io.File;
import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;


public class Sender {
    /*
     * 
     */
    public static void main(String[] args) {

        try{
            

            
            PrivateKey privXkey = keyGeneration.readPrivKeyFromFile("project01/KeyGen/XPrivate.key");
            System.out.println("privXkey:read");
            SecretKey symKey = readSymmetricKeyFromFile("project01/KeyGen/symmetric.key");
            encryptMessage( privXkey, symKey);
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
        try (FileOutputStream fos = new FileOutputStream(hashFile)) {
            fos.write(hash);
            System.out.println("SHA256(M) written to message.dd");
            fos.close();

        } catch (Exception e) {
            System.out.println("Error: " + e);
            sc.close();
            return;
        }
        
        
        // (RSA-En Kx– (SHA256 (M)) || M) 
        // Calculate RSA encryption of the hash using the private key of the sender (Kx-), concatenate the resulting ciphertext with M, and save the resulting ciphertext to a file called "message.ds"
        byte[] encryptedBytes = null;
        try{
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, privXkey);
        encryptedBytes = cipher.doFinal(hash);
        }

        catch(Exception e){
            System.out.println("Error: " + e);
            sc.close();
            return;
        }

        // Save this cypertext to a file called "message.ds-msg" and display the ciphertext in hexadecimal bytes
        File RSAEncryptedFile = new File("message.ds-msg");

        try (FileOutputStream fos = new FileOutputStream(RSAEncryptedFile)) {
            fos.write(encryptedBytes);
            System.out.println("Ciphertext written to message.ds-msg");
            fos.close();
        } catch (Exception e) {
            System.out.println("Error: " + e);
            sc.close();
            return;
        }

        System.out.println("Ciphertext After RSA:" + byteToHex(encryptedBytes));

        // Append M piece by piece to the file "message.ds-msg" 
        try (FileOutputStream fos = new FileOutputStream(RSAEncryptedFile, true)) {
            fos.write(messageBytes);
            System.out.println("Message appended to message.ds-msg");
            fos.close();
        } catch (Exception e) {
            System.out.println("Error: " + e);
            sc.close();
            return;
        }
        byte[] encryptedBytes2 = null;
        File AESEncryptedFile = new File("message.aecipher");
        // Calculate the AES encryption of the message using the symmetric key Kxy, where each piece is a multiple of 16 bytes
        // Save the resulting ciphertext to a file called "message.aecipher" and display the ciphertext in hexadecimal bytes
        try{
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); // AES/CBC/PKCS5Padding is a standard for symmetric encryption
            cipher.init(Cipher.ENCRYPT_MODE, symKey);
            encryptedBytes2 = cipher.doFinal(encryptedBytes);
            
        }
        catch(Exception e){
            System.out.println("Error: " + e);
            sc.close();
            return;
        }
        
        try(FileOutputStream fos = new FileOutputStream(AESEncryptedFile, true)){
            fos.write(encryptedBytes2);
            System.out.println("Ciphertext written to message.aecipher");
            fos.close();
            System.out.println("Ciphertext after AES: " + byteToHex(encryptedBytes2));
        }

        catch(Exception e){
            System.out.println("Error: " + e);
            sc.close();
            return;
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

