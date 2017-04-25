package ciphers.des_3des;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by roman on 12.2.17.
 * TDES is 3DES is TripleDES
 *
 * result of encryption TDES: packageName/resEncrypt2FileName or packageName/resEncryptBin2FileName
 * result of decryption TDES: packageName/resDecrypt3FileName or packageName/resDecryptBin3FileName
 */
public class TDES {
    private static void encryptDESkeyi(List<List<Integer>> blocks, List<List<Integer>> k,
                      List<Integer> left, List<Integer> right,
                      List<Integer> temp, String inputFilename,
                               String outputFilename, String outputBinFilename){
        blocks.clear();
        DES.binaryFromFile(blocks,inputFilename);
        DES.binaryToTerminal(blocks, "Plain text:");

        for (int i = 0; i < blocks.size(); i++){
            DES.doFirstPerm(blocks, i);
            DES.doCycle16(blocks,k,left,right,temp,i, true);
            DES.doRevLastPerm(blocks, i);
        }

        DES.binaryToTextTofile(blocks,outputFilename);
        DES.binaryToFile(blocks, outputBinFilename);
        DES.binaryToTerminal(blocks, "Encrypted:");
    }

    private static void decryptDESkeyi(List<List<Integer>> blocks, List<List<Integer>> k,
                        List<Integer> left, List<Integer> right,
                        List<Integer> temp, String outputFilename,
                               String outputBinFilename){
        for (int i=0; i< blocks.size(); i++){
            DES.doFirstPerm(blocks,i);
            DES.doCycle16(blocks,k,left,right,temp,i,false);
            DES.doRevLastPerm(blocks, i);
        }

        DES.binaryToTerminal(blocks,"Decrypted:");
        DES.binaryToTextTofile(blocks, outputFilename);
        DES.binaryToFile(blocks, outputBinFilename);

    }

    private static void getAllkeyiFromFile(List<List<Integer>> k, String inputFilename){
        k.clear();
        DES.keyFromFile(k, inputFilename);
        DES.getKey0(k);
        for (int j = 1; j <= 16; j++) {
            DES.getKeyi(k, j);
        }
    }

    /**
     * start encryption TDES
     */
    public static List<List<Integer>> encrypt(String packageName,
                               String inputData,
                               String inputKey1FileName,
                               String inputKey2FileName,
                               String inputKey3FileName,
                               String resEncrypt1FileName,
                               String resEncryptBin1FileName,
                               String resDecrypt1FileName,
                               String resDecryptBin1FileName,
                               String resEncrypt2FileName,
                               String resEncryptBin2FileName){
        List<List<Integer>> k = new ArrayList<>(),
                            blocks = new ArrayList<>();
        List<Integer> left = new ArrayList<>(),
                      right = new ArrayList<>(),
                      temp = new ArrayList<>();

        getAllkeyiFromFile(k,packageName.concat(inputKey1FileName));
        encryptDESkeyi(blocks,k,left,right,temp,
                packageName.concat(inputData),
                packageName.concat(resEncrypt1FileName),
                packageName.concat(resEncryptBin1FileName)
        );

        getAllkeyiFromFile(k,packageName.concat(inputKey2FileName));
        decryptDESkeyi(blocks,k,left,right,temp,
                packageName.concat(resDecrypt1FileName),
                packageName.concat(resDecryptBin1FileName));

        getAllkeyiFromFile(k,packageName.concat(inputKey3FileName));
        encryptDESkeyi(blocks,k,left,right,temp,
                packageName.concat(resDecrypt1FileName),
                packageName.concat(resEncrypt2FileName),
                packageName.concat(resEncryptBin2FileName)
        );

        return blocks;
    }

    /**
     * start decryption TDES
     */
    public static void decrypt(List<List<Integer>> blocks,
                               String packageName,
                               String inputKey1FileName,
                               String inputKey2FileName,
                               String inputKey3FileName,
                               String resDecrypt2FileName,
                               String resDecryptBin2FileName,
                               String resEncrypt3FileName,
                               String resEncryptBin3FileName,
                               String resDecrypt3FileName,
                               String resDecryptBin3FileName){
        List<List<Integer>> k = new ArrayList<>();
        List<Integer> left = new ArrayList<>(),
                      right = new ArrayList<>(),
                      temp = new ArrayList<>();

        getAllkeyiFromFile(k,packageName.concat(inputKey3FileName));
        decryptDESkeyi(blocks,k,left,right,temp,
                packageName.concat(resDecrypt2FileName),
                packageName.concat(resDecryptBin2FileName)
        );

        getAllkeyiFromFile(k,packageName.concat(inputKey2FileName));
        encryptDESkeyi(blocks,k,left,right,temp,
                packageName.concat(resDecrypt2FileName),
                packageName.concat(resEncrypt3FileName),
                packageName.concat(resEncryptBin3FileName)
        );

        getAllkeyiFromFile(k,packageName.concat(inputKey1FileName));
        decryptDESkeyi(blocks,k,left,right,temp,
                packageName.concat(resDecrypt3FileName),
                packageName.concat(resDecryptBin3FileName)
        );
    }
}
