package Sender;

import java.util.Scanner;
import java.io.File;
import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import KeyGen.keyGeneration;

public class sender {
    /*
     * 
     */
    public static void main(String[] args) {

        try{
        PublicKey pubXkey = keyGeneration.readPubKeyFromFile("XPublic.key");
        PublicKey pubYkey = keyGeneration.readPubKeyFromFile("YPublic.key");
        PrivateKey privXkey = keyGeneration.readPrivKeyFromFile("XPrivate.key");
        PrivateKey privYkey = keyGeneration.readPrivKeyFromFile("YPrivate.key");
        encryptMessage(pubXkey, pubYkey, privXkey, privYkey);
        }
        catch(Exception e){
            System.out.println("Error: " + e);
        }
        
        
        
        


    }

    private static void encryptMessage(PublicKey pubXkey, PublicKey pubYkey, PrivateKey privXkey, PrivateKey privYkey) {

        Scanner sc = new Scanner(System.in);
        System.out.println("Enter the name of the file containing the message to be encrypted(file must be in the same directory, or use full path): ");

        File message = null;
        try {
            message = new File(sc.nextLine());
        } catch (Exception e) {
            System.out.println("Error: " + e);
        }
        
        int chunkSize = 2048;
        byte[] messageBytes = new byte[chunkSize];


        // read the message file piece by piece, in a small multiple of 1024 bytes. 2048?
        try(BufferedInputStream bis = new BufferedInputStream(new FileInputStream(message))) {
            int bytesRead = 0;
            while((bytesRead = bis.read(messageBytes)) != -1) {
                System.out.println("Read " + bytesRead + " bytes");
            }
            System.out.println("Total bytes read: " + bytesRead);
            System.out.println("Message read successfully");

        } catch (Exception e) {
            System.out.println("Error: " + e);
        }

        // calculate the SHA256 hash of the entire message 
        byte[] hash = null;
        try{
            MessageDigest mDigest = MessageDigest.getInstance("SHA-256");
            hash = mDigest.digest(messageBytes);
        }

        catch(Exception e){
            System.out.println("Error: " + e);
        }
        
        // display the hash in hexadecimal bytes
        System.out.println("SHA256(M) = " + byteToHex(hash));


        // display  a prompt to the user : "do you want to invert the first byte in SHA256(M)? (y/n)"
        // if the user enters "y", invert the first byte in SHA256(M) and display the new hash
        System.out.println("Do you want to invert the first byte in SHA256(M)? (y/n)");
        String response = sc.nextLine();
        if (response.equals("y")||response.equals("Y")||response.equals("yes")||response.equals("Yes")) {
            hash[0] = (byte) ~hash[0]; // invert the first byte in SHA256(M)
            System.out.println("SHA256(M) = " + byteToHex(hash));
        }
        

        //save the hash to a file called "message.dd" and display SHA256(M) in hexadecimal bytes
        File hashFile = new File("message.dd");
        try (FileOutputStream fos = new FileOutputStream(hashFile)) {
            fos.write(hash);

            System.out.println("SHA256(M) written to message.dd");
            fos.close();

        } catch (Exception e) {
            System.out.println("Error: " + e);
        }
            
       
        // calculate the RSA encryption of the hash using the private key of the sender (Kx-)


        // Save this cypertext to a file called "message.ds-msg" and display the ciphertext in hexadecimal bytes
        // Append M piece by piece to the file "message.ds-msg" 
        // Calculate the AES encryption of the message using the symmetric key Kxy, where each piece is a multiple of 16 bytes

        // Save the resulting blocks to a file called "message.aecipher 

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

