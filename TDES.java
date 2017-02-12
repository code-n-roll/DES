package ciphers;

import java.util.List;

import static ciphers.DES.*;
/**
 * Created by roman on 12.2.17.
 */
public class TDES {
    static void encryptDESkeyi(List<List<Integer>> blocks, List<List<Integer>> k,
                      List<Integer> left, List<Integer> right,
                      List<Integer> temp, String inputFilename,
                               String outputFilename, String outputBinFilename){
        blocks.clear();
        binaryFromFile(blocks,inputFilename);
        binaryToTerminal(blocks, "Plain text:");

        for (int i = 0; i < blocks.size(); i++){
            doFirstPerm(blocks, i);
            doCycle16(blocks,k,left,right,temp,i, true);
            doRevLastPerm(blocks, i);
        }

        binaryToTextTofile(blocks,outputFilename);
        binaryToFile(blocks, outputBinFilename);
        binaryToTerminal(blocks, "Encrypted:");
    }

    static void decryptDESkeyi(List<List<Integer>> blocks, List<List<Integer>> k,
                        List<Integer> left, List<Integer> right,
                        List<Integer> temp, String outputFilename,
                               String outputBinFilename){
        for (int i=0; i< blocks.size(); i++){
            doFirstPerm(blocks,i);
            doCycle16(blocks,k,left,right,temp,i,false);
            doRevLastPerm(blocks, i);
        }

        binaryToTerminal(blocks,"Decrypted:");
        binaryToTextTofile(blocks, outputFilename);
        binaryToFile(blocks, outputBinFilename);

    }

    static void getAllkeyiFromFile(List<List<Integer>> k, String inputFilename){
        k.clear();
        keyFromFile(k, inputFilename);
        getKey0(k);
        for (int j = 1; j <= 16; j++) {
            getKeyi(k, j);
        }
    }
}
