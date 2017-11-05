package ciphers.des_3des.main;

import ciphers.des_3des.Des;

/**
 * Created by roman on 11.2.17.
 * Des - Data Encryption Standard
 *
 * result of encryption Des: packageName/encrypt.txt or packageName/encryptBin.txt
 * result of decryption Des: packageName/decrypt.txt or packageName/decryptBin.txt
 */
public class MainDes {
    public static void main(String[] args){
        Des.encrypt("/mnt/Data/Java/tasks/src/ciphers/des_3des/files/",
                "input.txt",
                "key56bits.txt",
                "resultDes.txt");
        Des.decrypt("/mnt/Data/Java/tasks/src/ciphers/des_3des/files/",
                "key56bits.txt",
                "resultDes.txt",
                "resultDesRev.txt");
    }
}
