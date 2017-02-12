package ciphers;

import java.util.ArrayList;
import java.util.List;

import static ciphers.DES.*;

/**
 * Created by roman on 11.2.17.
 */
public class MainDES {
    public static void main(String[] args){
        List<List<Integer>> k = new ArrayList<>(),
                blocks = new ArrayList<>();
        List<Integer> left = new ArrayList<>(),
                right = new ArrayList<>(),
                temp = new ArrayList<>();

        keyFromFile(k, "/media/roman/Data/Java/lab_OOP/src/ciphers/key56bits.txt");
        binaryFromFile(blocks,"/media/roman/Data/Java/lab_OOP/src/ciphers/input.txt");
        binaryToTerminal(blocks, "Plain text:");

        getKey0(k);
        for (int j = 1; j <= 16; j++) {
            getKeyi(k, j);
        }
        for (int i = 0; i < blocks.size(); i++){
            doFirstPerm(blocks, i);
            doCycle16(blocks,k,left,right,temp,i, true);
            doRevLastPerm(blocks, i);
        }

        binaryToTextTofile(blocks,"/media/roman/Data/Java/lab_OOP/src/ciphers/encrypt.txt");
        binaryToFile(blocks, "/media/roman/Data/Java/lab_OOP/src/ciphers/encryptBin.txt");
        binaryToTerminal(blocks, "Encrypted:");

        for (int i=0; i< blocks.size(); i++){
            doFirstPerm(blocks,i);
            doCycle16(blocks,k,left,right,temp,i,false);
            doRevLastPerm(blocks, i);
        }

        binaryToTerminal(blocks,"Decrypted:");
        binaryToTextTofile(blocks, "/media/roman/Data/Java/lab_OOP/src/ciphers/decrypt.txt");
        binaryToFile(blocks, "/media/roman/Data/Java/lab_OOP/src/ciphers/decryptBin.txt");
    }
}
