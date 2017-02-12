package ciphers;

import java.util.ArrayList;
import java.util.List;

import static ciphers.TDES.decryptDESkeyi;
import static ciphers.TDES.encryptDESkeyi;
import static ciphers.TDES.getAllkeyiFromFile;

/**
 * Created by roman on 12.2.17.
 * TDES is 3DES is TripleDES
 *
 * result of encryption TDES: encrypt2.txt/encryptBin2.txt
 * result of decryption TDES: decrypt3.txt/decryptBin3.txt
 */
public class MainTDES {
    public static void main(String[] args){
        List<List<Integer>> k = new ArrayList<>(),
        blocks = new ArrayList<>();
        List<Integer> left = new ArrayList<>(),
                right = new ArrayList<>(),
                temp = new ArrayList<>();

        /**
         * start encryption TDES
         */
        getAllkeyiFromFile(k,"/media/roman/Data/Java/lab_OOP/src/ciphers/key1TDES.txt");
        encryptDESkeyi(blocks,k,left,right,temp,
                "/media/roman/Data/Java/lab_OOP/src/ciphers/input.txt",
                "/media/roman/Data/Java/lab_OOP/src/ciphers/encrypt1.txt",
                "/media/roman/Data/Java/lab_OOP/src/ciphers/encryptBin1.txt"
        );

        getAllkeyiFromFile(k,"/media/roman/Data/Java/lab_OOP/src/ciphers/key2TDES.txt");
        decryptDESkeyi(blocks,k,left,right,temp,
                "/media/roman/Data/Java/lab_OOP/src/ciphers/decrypt1.txt",
                "/media/roman/Data/Java/lab_OOP/src/ciphers/decryptBin1.txt");

        getAllkeyiFromFile(k,"/media/roman/Data/Java/lab_OOP/src/ciphers/key3TDES.txt");
        encryptDESkeyi(blocks,k,left,right,temp,
                "/media/roman/Data/Java/lab_OOP/src/ciphers/decrypt1.txt",
                "/media/roman/Data/Java/lab_OOP/src/ciphers/encrypt2.txt",
                "/media/roman/Data/Java/lab_OOP/src/ciphers/encryptBin2.txt"
        );

        /**
         * start decryption TDES
         */
        getAllkeyiFromFile(k,"/media/roman/Data/Java/lab_OOP/src/ciphers/key3TDES.txt");
        decryptDESkeyi(blocks,k,left,right,temp,
                "/media/roman/Data/Java/lab_OOP/src/ciphers/decrypt2.txt",
                "/media/roman/Data/Java/lab_OOP/src/ciphers/decryptBin2.txt"
        );

        getAllkeyiFromFile(k,"/media/roman/Data/Java/lab_OOP/src/ciphers/key2TDES.txt");
        encryptDESkeyi(blocks,k,left,right,temp,
                "/media/roman/Data/Java/lab_OOP/src/ciphers/decrypt2.txt",
                "/media/roman/Data/Java/lab_OOP/src/ciphers/encrypt3.txt",
                "/media/roman/Data/Java/lab_OOP/src/ciphers/encryptBin3.txt");

        getAllkeyiFromFile(k,"/media/roman/Data/Java/lab_OOP/src/ciphers/key1TDES.txt");
        decryptDESkeyi(blocks,k,left,right,temp,
                "/media/roman/Data/Java/lab_OOP/src/ciphers/decrypt3.txt",
                "/media/roman/Data/Java/lab_OOP/src/ciphers/decryptBin3.txt"
        );
    }
}
