package ciphers.des_3des;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import static ciphers.des_3des.Constants.*;
import static ciphers.des_3des.IOUtil.*;

/**
 * Created by roman on 7.2.17.
 * DES - Data Encryption Standard
 *
 * result of encryption DES: packageName/encryptFileName or
 * packageName/encryptBinFileName.txt
 *
 * result of decryption DES: packageName/decryptFileName or
 * packageName/decryptBinFileName.txt
 */
public class DES {
    private final static int BITS64 = 64;
    private final static int BITS28 = 28;
    private final static int BITS56 = 56;
    private final static int BITS48 = 48;
    private final static int BITS32 = 32;
    private final static int BITS8 = 8;

    private static List<List<Integer>> k = new ArrayList<>();
    private static List<List<Integer>> blocks = new ArrayList<>();

    static List<Integer> f(final List<Integer> right,
                           final List<Integer> k){
        LinkedList<Integer> e = new LinkedList<>(right);

        for (int i= 0; i < BITS48; i++){
            if (i >= e.size()){
                e.add(right.get(funcExtE[i]-1));
            } else {
                e.set(i, right.get(funcExtE[i] - 1));
            }
        }
        for (int i = 0; i < BITS48; i++){
            e.set(i, e.get(i) ^ k.get(i));
        }

        List<Integer> eNew = new ArrayList<>();
        for (int i = 0; i < BITS8; i++) {
            LinkedList<Integer> bits6 =
                    new LinkedList<>(e.subList(i * 6, i * 6 + 6));
            String frontLast = bits6.getFirst().toString()
                    + bits6.getLast().toString();
            bits6.removeFirst();
            bits6.removeLast();
            String bits4 = "";
            for (int bit : bits6) {
                bits4 = bits4.concat(String.valueOf(bit));
            }
            int a = Integer.parseInt(frontLast, 2);
            int b = Integer.parseInt(bits4, 2);

            String fromStable = Integer.toBinaryString(s[i][a * 16 + b]);
            fromStable = String.format("%04d", Integer.parseInt(fromStable));
            for (String s : fromStable.split("(?!^)")){
                eNew.add(Integer.parseInt(s));
            }
        }

        List<Integer> eNewTemp = new ArrayList<>(eNew);
        for (int i = 0; i < BITS32; i++){
            eNew.set(i, eNewTemp.get(permP[i]-1));
        }

        return eNew;
    }

    static List<Integer> sumByMod2(List<Integer> left,
                                   List<Integer> right,
                                   List<Integer> k){
        List<Integer> res = left;
        List<Integer> resf = f(right, k);
        for (int i = 0; i< left.size(); i++){
            res.set(i,(left.get(i) ^ resf.get(i)));
        }
        return res;
    }

    static void getKey0(List<List<Integer>> k){
        int sum1 = 0;
        for (int j = 1; j <= BITS64; j++){
            if (j % 8 == 0) {
                if (sum1 % 2 == 0){
                    k.get(0).add(j-1,1);
                } else {
                    k.get(0).add(j-1,0);
                }
                sum1 = 0;
                continue;
            }
            if (k.get(0).get(j-1) == 1){
                sum1++;
            }
        }

        List<Integer> oldKey = new ArrayList<>(k.get(0));
        for (int j = 0; j < BITS28; j++){
            k.get(0).set(j, oldKey.get(c0[j]-1));
        }
        for (int j = BITS28; j < BITS56; j++){
            k.get(0).set(j, oldKey.get(d0[j%BITS28]-1));
        }
    }

    static void getKeyi(List<List<Integer>> k, int i){
        int temp;
        LinkedList<Integer> left28Key =
                new LinkedList<>(k.get(0).subList(0,BITS28)),
        right28Key = new LinkedList<>(k.get(0).subList(BITS28,BITS56));
        for (int z = 0; z < i; z++) {
            for (int j = 0; j < nshifts[z]; j++) {
                temp = left28Key.removeFirst();
                left28Key.add(temp);
                temp = right28Key.removeFirst();
                right28Key.add(temp);
            }
        }
        left28Key.addAll(right28Key);

        List<Integer> tempListPrev = new ArrayList<>(left28Key);
        for (int j = 0; j < BITS48; j++){
            left28Key.set(j, tempListPrev.get(bits56to48[j]-1));
        }
        k.add(new LinkedList<>(left28Key.subList(0,BITS48)));
    }

    static void doRevLastPerm(List<List<Integer>> blocks, int i) {
        List<Integer> iTempBlock = new ArrayList<>(blocks.get(i));
        for (int j = 0; j < BITS64; j++){
            blocks.get(i).set(j, iTempBlock.get(revLastPerm[j]-1));
        }
    }

    static void doFirstPerm(List<List<Integer>> blocks, int i){
        List<Integer> iTempBlock = new ArrayList<>(blocks.get(i));
        for (int j = 0; j < blocks.get(i).size(); j++){
            blocks.get(i).set(j, iTempBlock.get(firstPermutation[j]-1));
        }
    }

    static void doCycle16(List<List<Integer>> blocks,
                          List<List<Integer>> k,
                          int i,
                          boolean encryption){
        List<Integer> left = blocks.get(i).subList(0,BITS32);
        List<Integer> right = blocks.get(i).subList(BITS32, BITS64);
        List<Integer> temp;

        if (encryption) {
            for (int j = 1; j <= 16; j++) {
                temp = left;
                left = right;
                right = sumByMod2(temp, right, k.get(j));
            }
        } else {
            for (int j = 16; j >= 1; j--){
                temp = right;
                right = left;
                left = sumByMod2(temp, left, k.get(j));
            }
        }

        left.addAll(right);
        blocks.set(i, left);
    }

    /**
     * start encryption DES
     */
    public static void encrypt(final String packageName,
                               final String inputDataFileName,
                               final String inputKeyFileName,
                               final String encryptFileName,
                               final String encryptBinFileName){
        keyFromFile(k, packageName.concat(inputKeyFileName));
        binaryFromFile(blocks,packageName.concat(inputDataFileName));
        binaryToTerminal(blocks, "Plain text:");

        getKey0(k);
        for (int j = 1; j <= 16; j++) {
            getKeyi(k, j);
        }
        for (int i = 0; i < blocks.size(); i++){
            doFirstPerm(blocks, i);
            doCycle16(blocks, k, i, true);
            doRevLastPerm(blocks, i);
        }

        binaryToTextTofile(blocks,packageName.concat(encryptFileName));
        binaryToFile(blocks, packageName.concat(encryptBinFileName));
        binaryToTerminal(blocks, "Encrypted:");
    }

    /**
     * start decryption DES
     */
    public static void decrypt(final String packageName,
                               final String inputKeyFileName,
                               final String encryptFileName,
                               final String decryptFileName,
                               final String decryptBinFileName){
        k.clear();
        blocks.clear();

        keyFromFile(k, packageName.concat(inputKeyFileName));
        binaryFromFile(blocks,packageName.concat(encryptFileName));
        binaryToTerminal(blocks, "Plain text:");

        getKey0(k);
        for (int j = 1; j <= 16; j++) {
            getKeyi(k, j);
        }
        for (int i = 0; i < blocks.size(); i++){
            doFirstPerm(blocks,i);
            doCycle16(blocks, k, i,false);
            doRevLastPerm(blocks, i);
        }

        binaryToTerminal(blocks,"Decrypted:");
        binaryToTextTofile(blocks, packageName.concat(decryptFileName));
        binaryToFile(blocks, packageName.concat(decryptBinFileName));
    }
}