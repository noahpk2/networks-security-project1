package Reciever;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import KeyGen.keyGeneration;


public class Receiver {

public static void main(String[] args) {
    Receiver receiver = new Receiver();
    receiver.decryptMessage();
    
}

public static SecretKey readSymmetricKeyFromFile(String keyFileName) throws IOException {
    byte[] keyBytes = Files.readAllBytes(Paths.get(keyFileName));
    return new SecretKeySpec(keyBytes, "AES");
    }


public void decryptMessage() {
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
pubXKey = keyGeneration.readPubKeyFromFile("project01/KeyGen/XPublic.key");
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
System.out.println("Input the name of the message file: ");
String messageFileName = sc.nextLine();

/* 
4 Read the ciphertext, C, from the file “message.aescipher” block by block, where each block needs to be a multiple of 16
bytes long. (Hint: if the length of the last block is less than that multiple of 16 bytes, it needs to be placed in a byte array
whose array size is the length of the last piece before being decrypted.) Calculate the AES Decryption of C using Kxy
block by block to get RSA-En Kx - (SHA256 (M)) || M, and save the resulting pieces into a file named “message.ds-msg”.
*/
byte[] encryptedBytes = null;

int blockSize = 16;



try{
    
    Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
    cipher.init(Cipher.DECRYPT_MODE, symKey);
    // decrypt AES
    encryptedBytes = Files.readAllBytes(encryptedMessage.toPath());
    for (int i = 0; i < encryptedBytes.length; i += blockSize) {
        int end = Math.min(i + blockSize, encryptedBytes.length);
        byte[] block = Arrays.copyOfRange(encryptedBytes, i, end);
        byte[] decryptedBytes = cipher.doFinal(block);   
        try (FileOutputStream fos = new FileOutputStream("message.ds-msg", true)) {
        fos.write(decryptedBytes);
    }
    }
}
catch(Exception e){
    System.out.println("Error: " + e);
    e.printStackTrace();
    return;
}



try{
    /* 
5 If using "RSA/ECB/PKCS1Padding", read the first 128 bytes from the file “message.ds-msg” to get the digital signature
RSA-En Kx- (SHA256 (M)), and copy the message M, i.e., the leftover bytes in the file “message.ds-msg”, to a file whose
name is specified in Step 3. (Why 128 bytes? Why is the leftover M?) Calculate the RSA Decryption of this digital
signature using Kx+ to get the digital digest SHA256(M), SAVE this digital digest into a file named “message.dd”, and
DISPLAY it in Hexadecimal bytes.
*/
byte[] fileContent = Files.readAllBytes(new File("message.ds-msg").toPath());
byte[] digitalSignature = Arrays.copyOfRange(fileContent, 0, 128);
byte[] messageBytes = Arrays.copyOfRange(fileContent, 128, fileContent.length);

Files.write(Paths.get(messageFileName), messageBytes);

Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
cipher.init(Cipher.DECRYPT_MODE,pubXKey);
byte[] decryptedBytes = cipher.doFinal(digitalSignature);

Files.write(Paths.get("message.dd"), decryptedBytes);
System.out.println("SHA256(M): " + byteToHex(decryptedBytes));

}

catch(Exception e){
    System.out.println("Error: " + e);
    return;
}


    /* 
6 Read the message M from the file whose name is specified in Step 3 piece by piece, where each piece is recommended to
be a small multiple of 1024 bytes, calculate the SHA256 hash value (digital digest) of the entire message M, DISPLAY it
in Hexadecimal bytes, compare it with the digital digest obtained in Step 5, display whether the digital digest passes the
authentication check.
 */
byte[] messageBytes = null;

try{
    messageBytes = Files.readAllBytes(new File(messageFileName).toPath());
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    byte[] messageHash = md.digest(messageBytes);
    String messageHashHex = byteToHex(messageHash);
    System.out.println("SHA256(M): " + messageHashHex);

    byte[] digitalDigest = Files.readAllBytes(new File("message.dd").toPath());
    String digitalDigestHex = byteToHex(digitalDigest);

    if (messageHashHex.equals(digitalDigestHex)) {
        System.out.println("The digital digest passes the authentication check.");
    } else {
        System.out.println("The digital digest does not pass the authentication check.");
    }
}

catch(Exception e){
    System.out.println("Error: " + e);
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
