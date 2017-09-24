package ciphers.des_3des;

/**
 * Created by roman on 11.2.17.
 * DES - Data Encryption Standard
 *
 * result of encryption DES: packageName/encrypt.txt or packageName/encryptBin.txt
 * result of decryption DES: packageName/decrypt.txt or packageName/decryptBin.txt
 */
public class MainDES {
    public static void main(String[] args){
        DES.encrypt("/mnt/Data/Java/tasks/src/ciphers/des_3des/files/",
                "input.txt",
                "key56bits.txt",
                "encrypt.txt",
                "encryptBin.txt");
        DES.decrypt("/mnt/Data/Java/tasks/src/ciphers/des_3des/files/",
                "key56bits.txt",
                "encrypt.txt",
                "decrypt.txt",
                "decryptBin.txt");

    }
}
