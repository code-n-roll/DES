package ciphers.des_3des;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class IOUtil {
    private static int BITS64 = 64;

    static void binaryFromFile(List<List<Integer>> blocks,
                               final String filename){
        try {
            List<Integer> buf = new ArrayList<>();
            FileInputStream file = new FileInputStream(filename);
            String bits64 = "";
            int size = file.available(), symbol;
            char[] dst = new char[BITS64];

            System.out.println("File description"+
                    "\n\tpath: "+filename+
                    "\n\tsize: "+size+" bytes");

            for (int i = 1; i <= size; i++) {
                String bits8 = String.format("%08d", Integer
                        .parseInt(Integer.toBinaryString(file.read())));
                bits64 = bits64.concat(bits8);

                if ((i % 8 == 0 || i == size) && i != 0) {
                    bits64.getChars(0, bits64.length(), dst, 0);
                    for (char c : dst) {
                        if (c == Character.MIN_VALUE){
                            buf.add(0);
                        } else {
                            symbol = Integer.parseInt(String.valueOf(c));
                            buf.add(symbol);
                        }
                    }
                    blocks.add(new ArrayList<>(buf));

                    buf.clear();
                    bits64 = "";
                    Arrays.fill(dst, Character.MIN_VALUE);
                }
            }
        }catch (IOException e){
            e.printStackTrace();
        }
    }

    static void binaryToTerminal(final List<List<Integer>> blocks,
                                 final String descr){
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

    static void binaryToTextTofile(final List<List<Integer>> blocks,
                                   final String filename){
        try {
            FileOutputStream f = new FileOutputStream(filename);
            char ch;
            for (int i = 0; i < blocks.size(); i++) {
                for (int j = 0; j < 8; j++) {
                    List<Integer> octet = blocks.get(i)
                            .subList(j * 8, j * 8 + 8);
                    String bitSet = "";
                    for (int bit : octet) {
                        bitSet = bitSet.concat(String.valueOf(bit));
                    }
                    ch = (char) Integer.parseInt(bitSet, 2);
                    f.write(ch);
                }
            }
        } catch (IOException e){
            e.printStackTrace();
        }
    }

    static void binaryToFile(final List<List<Integer>> blocks,
                             final String filename){
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

    static void keyFromFile(List<List<Integer>> k,
                            final String filename){
        try {
            FileInputStream f = new FileInputStream(filename);
            List<Integer> bitset = new ArrayList<>();
            int character = f.read();
            while(character != -1){
                String octet = String.format("%08d",Integer
                        .parseInt(Integer.toBinaryString(character)));
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
