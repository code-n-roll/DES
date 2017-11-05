package ciphers.des_3des;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

import static ciphers.des_3des.IOUtil.*;
import static ciphers.des_3des.Constants.*;

/**
 * Created by roman on 12.2.17.
 * TDes is 3DES is TripleDES
 *
 * result of encryption TDes: packageName/resEncrypt2FileName
 * or packageName/resEncryptBin2FileName
 * result of decryption TDes: packageName/resDecrypt3FileName
 * or packageName/resDecryptBin3FileName
 */
public class TDes {
    private static void encryptDESkeyi(List<List<Integer>> blocks,
                                       List<List<Integer>> k,
                                       String inputFilename,
                                       String outputFilename,
                                       String outputBinFilename) {
        blocks.clear();
        binaryFromFile(blocks,inputFilename);
        binaryToTerminal(blocks, "Plain text:");

        for (int i = 0; i < blocks.size(); i++){
            Des.doFirstPerm(blocks, i);
            Des.doCycle16(blocks, k, i, true);
            Des.doRevLastPerm(blocks, i);
        }

        binaryToTextTofile(blocks,outputFilename);
        binaryToFile(blocks, outputBinFilename);
        binaryToTerminal(blocks, "Encrypted:");
    }

    private static void decryptDESkeyi(List<List<Integer>> blocks,
                                       List<List<Integer>> k,
                                       String outputFilename,
                                       String outputBinFilename) {
        for (int i=0; i< blocks.size(); i++){
            Des.doFirstPerm(blocks,i);
            Des.doCycle16(blocks, k, i,false);
            Des.doRevLastPerm(blocks, i);
        }

        binaryToTerminal(blocks,"Decrypted:");
        binaryToTextTofile(blocks, outputFilename);
        binaryToFile(blocks, outputBinFilename);

    }

    private static void getAllkeyiFromFile(List<List<Integer>> k,
                                           String inputFilename) {
        k.clear();
        keyFromFile(k, inputFilename);
        Des.getKey0(k);
        for (int j = 1; j <= 16; j++) {
            Des.getKeyi(k, j);
        }
    }

    /**
     * start encryption TDes
     */
    public static List<List<Integer>> encrypt(String packageName,
                                              String dataFromFile,
                                              String key1FileName,
                                              String key2FileName,
                                              String key3FileName,
                                              String resultFileName) {
        List<List<Integer>> k = new ArrayList<>(),
                blocks = new ArrayList<>();

        getAllkeyiFromFile(k,packageName.concat(key1FileName));
        encryptDESkeyi(blocks, k, packageName.concat(dataFromFile),
                packageName.concat(ENCRYPT1_FILENAME + FILE_FORMATE),
                packageName.concat(ENCRYPT1_FILENAME + BIN_SUFFIX
                        + FILE_FORMATE)
        );

        getAllkeyiFromFile(k,packageName.concat(key2FileName));
        decryptDESkeyi(blocks, k, packageName.concat(DECRYPT1_FILENAME
                        + FILE_FORMATE),
                packageName.concat(DECRYPT1_FILENAME + BIN_SUFFIX
                        + FILE_FORMATE));

        getAllkeyiFromFile(k,packageName.concat(key3FileName));
        encryptDESkeyi(blocks, k, packageName.concat(DECRYPT1_FILENAME
                        + FILE_FORMATE),
                packageName.concat(resultFileName),
                packageName.concat(resultFileName.replace(".",
                        BIN_SUFFIX + "."))
        );

        try {
            Files.delete(FileSystems.getDefault().getPath(packageName,
                    ENCRYPT1_FILENAME + FILE_FORMATE));
            Files.delete(FileSystems.getDefault().getPath(packageName,
                    ENCRYPT1_FILENAME + BIN_SUFFIX + FILE_FORMATE));
            Files.delete(FileSystems.getDefault().getPath(packageName,
                    DECRYPT1_FILENAME + FILE_FORMATE));
            Files.delete(FileSystems.getDefault().getPath(packageName,
                    DECRYPT1_FILENAME + BIN_SUFFIX + FILE_FORMATE));
        } catch (IOException e) {
            e.printStackTrace();
        }
        return blocks;
    }

    /**
     * start decryption TDes
     */
    public static void decrypt(List<List<Integer>> blocks,
                               String packageName,
                               String key1FileName,
                               String key2FileName,
                               String key3FileName,
                               String resultFileName) {
        List<List<Integer>> k = new ArrayList<>();

        getAllkeyiFromFile(k,packageName.concat(key3FileName));
        decryptDESkeyi(blocks, k, packageName.concat(DECRYPT2_FILENAME
                        + FILE_FORMATE),
                packageName.concat(DECRYPT2_FILENAME + BIN_SUFFIX
                        + FILE_FORMATE)
        );

        getAllkeyiFromFile(k,packageName.concat(key2FileName));
        encryptDESkeyi(blocks, k, packageName.concat(DECRYPT2_FILENAME
                        + FILE_FORMATE),
                packageName.concat(ENCRYPT3_FILENAME + FILE_FORMATE),
                packageName.concat(ENCRYPT3_FILENAME + BIN_SUFFIX
                        + FILE_FORMATE)
        );

        getAllkeyiFromFile(k,packageName.concat(key1FileName));
        decryptDESkeyi(blocks, k, packageName.concat(resultFileName),
                packageName.concat(resultFileName.replace(".",
                        BIN_SUFFIX + "."))
        );

        try {
            Files.delete(FileSystems.getDefault().getPath(packageName,
                    DECRYPT2_FILENAME + FILE_FORMATE));
            Files.delete(FileSystems.getDefault().getPath(packageName,
                    DECRYPT2_FILENAME + BIN_SUFFIX + FILE_FORMATE));
            Files.delete(FileSystems.getDefault().getPath(packageName,
                    ENCRYPT3_FILENAME + FILE_FORMATE));
            Files.delete(FileSystems.getDefault().getPath(packageName,
                    ENCRYPT3_FILENAME + BIN_SUFFIX + FILE_FORMATE));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}