// snippet in sender program to take symmetric key (in a byte output) and store in a byte array.

//symkeyfile is a binary file.


//first, open the file into a buffered input stream.

import java.io.BufferedInputStream;
import java.io.FileInputStream;



class Scratch{
    public static void main(String[] args){


        final int BUFFER_SIZE = 16; // default , could be different?
        try{
        BufferedInputStream symKeyFile = new BufferedInputStream(new FileInputStream("symmetric.key"), BUFFER_SIZE);
        byte[] symKey = new byte[BUFFER_SIZE];
        symKeyFile.read(symKey, 0, BUFFER_SIZE);
        symKeyFile.close();
        }

        catch(Exception e) {
            // IOException or FileNotFound Exception.
            System.out.println(e);
        }
    }


}