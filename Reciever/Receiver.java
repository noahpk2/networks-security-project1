package Reciever;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Scanner;

import javax.crypto.Cipher;
import KeyGen.keyGeneration;


public class Receiver {

public static void main(String[] args) {
    
}


public void decryptMessage() {
    /*
in the receiver’s program in the directory “Receiver”, using AES and RSA Decryptions to get SHA256 (M) and M, compare
SHA256(M) with the locally calculated SHA256 hash of M, report hashing error if any, and then save M to a file.
*/

PublicKey pubXKey = null;
PublicKey symKey = null;
File encryptedMessage = null;
/* 
1 To test this program, the corresponding key files need to be copied here from the directory “KeyGen”, and the file
“message.aescipher” needs to be copied here from the directory “Sender”.
*/ 
//2 Read the information on the keys to be used in this program from the key files and generate Kx+ and Kxy.

try{
pubXKey = keyGeneration.readPubKeyFromFile("KeyGen/XPublic.key");
symKey = keyGeneration.readPubKeyFromFile("KeyGen/symmetric.key");
encryptedMessage = new File("message.aescipher");
}
catch(Exception e){
    System.out.println("Error: " + e);
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
    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    Cipher cipher2 = Cipher.getInstance("AES/ECB/PKCS5Padding");

    cipher.init(Cipher.DECRYPT_MODE, pubXKey);
    cipher2.init(Cipher.DECRYPT_MODE, symKey);

    // decrypt AES
    encryptedBytes = Files.readAllBytes(encryptedMessage.toPath());
    for (int i = 0; i < encryptedBytes.length; i += blockSize) {
        int end = Math.min(i + blockSize, encryptedBytes.length);
        byte[] block = Arrays.copyOfRange(encryptedBytes, i, end);
        byte[] decryptedBytes = cipher2.doFinal(block);   
        try (FileOutputStream fos = new FileOutputStream("message.ds-msg", true)) {
        fos.write(decryptedBytes);
    }
    }
    /* 
5 If using "RSA/ECB/PKCS1Padding", read the first 128 bytes from the file “message.ds-msg” to get the digital signature
RSA-En Kx - (SHA256 (M)), and copy the message M, i.e., the leftover bytes in the file “message.ds-msg”, to a file whose
name is specified in Step 3. (Why 128 bytes? Why is the leftover M?) Calculate the RSA Decryption of this digital
signature using Kx+ to get the digital digest SHA256(M), SAVE this digital digest into a file named “message.dd”, and
DISPLAY it in Hexadecimal bytes.
*/

    
    

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
    


}
}
