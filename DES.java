package ciphers;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

/**
 * Created by roman on 7.2.17.
 */
public class DES {

    static int[] firstPermutation = {
        58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
    };

    static int[] funcExtE = {
        32, 1, 	 2,  3,  4,  5,
        4, 	5, 	 6,  7,  8,  9,
        8, 	9, 	10,	11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29,	30, 31, 32,  1
    };

    static int[] c0 = {
        57, 49, 41, 33, 25, 17,9,1,58,50,42,34,26,18,
        10, 2,59,51,43,35,27,19,11,3,60,52,44,36
    };
    static int[] d0 = {
        63,55,47,39,31,23,15,7,62,54,46,38,30,22,
        14,6,61,53,45,37,29,21,13,5,28,20,12,4
    };

    static int[] nshifts = {
        1,	1,	2,	2,	2,	2,	2,	2,	1,	2,	2,	2,	2,	2,	2,	1
    };

    static int[] bits56to48 = {
        14,	17,	11,	24,	1,	5,	3,	28,	15,	6,	21,	10,	23,	19,	12,	4,
        26,	8,	16,	7,	27,	20,	13,	2,	41,	52,	31,	37,	47,	55,	30,	40,
        51,	45,	33,	48,	44,	49,	39,	56,	34,	53,	46,	42,	50,	36,	29,	32
    };

    static int[][] s= {
        {
            14,	4,	13,	1,	2,	15,	11,	8,	3,	10,	6,	12,	5,	9,	0,	7,
            0,	15,	7,	4,	14,	2,	13,	1,	10,	6,	12,	11,	9,	5,	3,	8,
            4,	1,	14,	8,	13,	6,	2,	11,	15,	12,	9,	7,	3,	10,	5,	0,
            15,	12,	8,	2,	4,	9,	1,	7,	5,	11,	3,	14,	10,	0,	6,	13
        },
        {
            15,	1,	8,	14,	6,	11,	3,	4,	9,	7,	2,	13,	12,	0,	5,	10,
            3,	13,	4,	7,	15,	2,	8,	14,	12,	0,	1,	10,	6,	9,	11,	5,
            0,	14,	7,	11,	10,	4,	13,	1,	5,	8,	12,	6,	9,	3,	2,	15,
            13,	8,	10,	1,	3,	15,	4,	2,	11,	6,	7,	12,	0,	5,	14,	9
        },
        {
            10,	0,	9,	14,	6,	3,	15,	5,	1,	13,	12,	7,	11,	4,	2,	8,
            13,	7,	0,	9,	3,	4,	6,	10,	2,	8,	5,	14,	12,	11,	15,	1,
            13,	6,	4,	9,	8,	15,	3,	0,	11,	1,	2,	12,	5,	10,	14,	7,
            1,	10,	13,	0,	6,	9,	8,	7,	4,	15,	14,	3,	11,	5,	2,	12
        }
        ,{
            7,	13,	14,	3,	0,	6,	9,	10,	1,	2,	8,	5,	11,	12,	4,	15,
            13,	8,	11,	5,	6,	15,	0,	3,	4,	7,	2,	12,	1,	10,	14,	9,
            10,	6,	9,	0,	12,	11,	7,	13,	15,	1,	3,	14,	5,	2,	8,	4,
            3,	15,	0,	6,	10,	1,	13,	8,	9,	4,	5,	11,	12,	7,	2,	14
        }
        ,{
            2,	12,	4,	1,	7,	10,	11,	6,	8,	5,	3,	15,	13,	0,	14,	9,
            14,	11,	2,	12,	4,	7,	13,	1,	5,	0,	15,	10,	3,	9,	8,	6,
            4,	2,	1,	11,	10,	13,	7,	8,	15,	9,	12,	5,	6,	3,	0,	14,
            11,	8,	12,	7,	1,	14,	2,	13,	6,	15,	0,	9,	10,	4,	5,	3
        }
        ,{
            12,	1,	10,	15,	9,	2,	6,	8,	0,	13,	3,	4,	14,	7,	5,	11,
            10,	15,	4,	2,	7,	12,	9,	5,	6,	1,	13,	14,	0,	11,	3,	8,
            9,	14,	15,	5,	2,	8,	12,	3,	7,	0,	4,	10,	1,	13,	11,	6,
            4,	3,	2,	12,	9,	5,	15,	10,	11,	14,	1,	7,	6,	0,	8,	13
        },
        {
            4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
            13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
            1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
            6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12
        },
        {
            13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
            1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
            7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
            2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
        }
    };

    static int[] permP = {
        16,7,20,21,29,12,28,17,
        1,15,23,26,5,18,31,10,
        2,8,24,14,32,27,3,9,
        19,13,30,6,22,11,4,25
    };

    static int[] revLastPerm = {
        40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,
        38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,
        36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,
        34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25
    };

    static int BITS64 = 64, BITS28 = 28, BITS56 = 56, BITS48 = 48, BITS32 = 32, BITS8 = 8;

    static List<Integer> f(List<Integer> right, List<Integer> k){
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
            LinkedList<Integer> bits6 = new LinkedList<>(e.subList(i * 6, i * 6 + 6));
            String frontLast = bits6.getFirst().toString() + bits6.getLast().toString();
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

    static List<Integer> sumByMod2(List<Integer> left, List<Integer> right, List<Integer> k){
        List<Integer> res = left,
                resf = f(right, k);
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
        LinkedList<Integer> left28Key = new LinkedList<>(k.get(0).subList(0,BITS28)),
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
        for (int j=0; j < BITS64; j++){
            blocks.get(i).set(j, iTempBlock.get(revLastPerm[j]-1));
        }
    }

    static void doFirstPerm(List<List<Integer>> blocks, int i){
        List<Integer> iTempBlock = new ArrayList<>(blocks.get(i));
        for (int j=0; j < blocks.get(i).size(); j++){
            blocks.get(i).set(j, iTempBlock.get(firstPermutation[j]-1));
        }
    }

    static void doCycle16(List<List<Integer>> blocks, List<List<Integer>> k, List<Integer> left,
                          List<Integer> right, List<Integer> temp, int i, boolean encr){
        left = blocks.get(i).subList(0,BITS32);
        right = blocks.get(i).subList(BITS32,BITS64);

        if (encr) {
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

    static void binaryFromFile(List<List<Integer>> blocks, String filename){
        try {
            List<Integer> buf = new ArrayList<>();
            FileInputStream f = new FileInputStream(filename);
            String bits64 = "";
            int size = f.available(), sym;
            char[] dst = new char[BITS64];

            System.out.println("File description"+
                    "\n\tpath: "+filename+
                    "\n\tsize: "+size+" bytes");

            for (int i = 0; i < size; i++) {
                if ((i % 8 == 0 || i == size - 1) && i != 0) {
                    bits64.getChars(0, bits64.length(), dst, 0);
                    for (char c : dst) {
                        if (c == Character.MIN_VALUE){
                            buf.add(0);
                        } else {
                            sym = Integer.parseInt(String.valueOf(c));
                            buf.add(sym);
                        }
                    }
                    blocks.add(new ArrayList<>(buf));

                    buf.clear();
                    bits64 = "";
                    Arrays.fill(dst, Character.MIN_VALUE);
                }
                String bits8 = String.format("%08d", Integer.parseInt(Integer.toBinaryString(f.read())));
                bits64 = bits64.concat(bits8);
            }
        }catch (IOException e){
            e.printStackTrace();
        }
    }

    static void binaryToTerminal(List<List<Integer>> blocks, String descr){
        System.out.println("\n"+descr);
        for (int i = 0; i< blocks.size(); i++){
            for (int j = 0; j< blocks.get(i).size(); j++) {
                if (j % 8 == 0 && j != 0){
                    System.out.print(" ");
                }
                System.out.print(blocks.get(i).get(j));
            }
            System.out.println();
        }
    }

    static void binaryToTextTofile(List<List<Integer>> blocks, String filename){
        try {
            FileOutputStream f = new FileOutputStream(filename);
            char ch;
            for (int i = 0; i < blocks.size(); i++) {
                for (int j = 0; j < 8; j++) {
                    List<Integer> octet = blocks.get(i).subList(j * 8, j * 8 + 8);
                    String bitSet = "";
                    for (int bit : octet) {
                        bitSet += String.valueOf(bit);
                    }
                    ch = (char) Integer.parseInt(bitSet, 2);
                    f.write(ch);
                }
            }
        } catch (IOException e){
            e.printStackTrace();
        }
    }

    static void binaryToFile(List<List<Integer>> blocks, String filename){
        try {
            FileOutputStream f = new FileOutputStream(filename);
            for (int i = 0; i < blocks.size(); i++) {
                for (int j = 0; j < blocks.get(i).size(); j++) {
                    if (j % 8 == 0 && j != 0) {
                        f.write(' ');
                    }
                    f.write(String.valueOf(blocks.get(i).get(j)).getBytes());
                }
                f.write('\n');
            }
        } catch (IOException e){
            e.printStackTrace();
        }
    }

    static void keyFromFile(List<List<Integer>> k, String filename){
        try {
            FileInputStream f = new FileInputStream(filename);
            List<Integer> bitset = new ArrayList<>();
            int character = f.read();
            while(character != -1){
                String octet = String.format("%08d",Integer.parseInt(Integer.toBinaryString(character)));
                for (String bit : octet.split("(?!^)")){
                    bitset.add(Integer.parseInt(bit));
                }
                k.add(bitset);
                character = f.read();
            }
        } catch (IOException e){
            e.printStackTrace();
        }
    }
}