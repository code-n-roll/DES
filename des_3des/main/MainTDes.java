package ciphers.des_3des.main;

import ciphers.des_3des.TDes;

import java.util.List;

/**
 * Created by roman on 12.2.17.
 * TDes is 3DES is TripleDES
 *
 * result of encryption TDes: encrypt2.txt/encryptBin2.txt
 * result of decryption TDes: decrypt3.txt/decryptBin3.txt
 */
public class MainTDes {
    public static void main(String[] args){
        List<List<Integer>> blocks;

        blocks = TDes.encrypt("/mnt/Data/Java/tasks/src/ciphers/des_3des/files/",
                "input.txt",
                "key1TDES.txt",
                "key2TDES.txt",
                "key3TDES.txt",
                "resultTDes.txt");

        TDes.decrypt(blocks,"/mnt/Data/Java/tasks/src/ciphers/des_3des/files/",
                "key1TDES.txt",
                "key2TDES.txt",
                "key3TDES.txt",
                "resultTDesRev.txt");
    }
}
