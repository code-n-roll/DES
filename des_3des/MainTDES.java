package ciphers.des_3des;

import java.util.List;

/**
 * Created by roman on 12.2.17.
 * TDES is 3DES is TripleDES
 *
 * result of encryption TDES: encrypt2.txt/encryptBin2.txt
 * result of decryption TDES: decrypt3.txt/decryptBin3.txt
 */
public class MainTDES {
    public static void main(String[] args){
        List<List<Integer>> blocks;
        blocks = TDES.encrypt("/media/roman/Data/Java/tasks/src/ciphers/des_3des/files/",
                "input.txt",
                "key1TDES.txt",
                "key2TDES.txt",
                "key3TDES.txt",
                "encrypt1.txt",
                "encryptBin1.txt",
                "decrypt1.txt",
                "decryptBin1.txt",
                "encrypt2.txt",
                "encryptBin2.txt");

        TDES.decrypt(blocks,"/media/roman/Data/Java/tasks/src/ciphers/des_3des/files/",
                "key1TDES.txt",
                "key2TDES.txt",
                "key3TDES.txt",
                "decrypt2.txt",
                "decryptBin2.txt",
                "encrypt3.txt",
                "encryptBin3.txt",
                "decrypt3.txt",
                "decryptBin3.txt");
    }
}
