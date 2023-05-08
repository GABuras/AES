// George Adler Buras

// Although AES generally supports 128, 192, and 256-bit keys and uses 10, 12, or 14
// rounds to encrypt respectively, depending on the key size, this example implementation's
// scope is limited to only support 10 rounds of encryption with a 128-bit key

package com.mycompany.aes;

import java.util.*;

public class AES {
    
    // Subsitution table for encryption
    private final static String[] sBoxEncrypt = {
        /*          0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f */
        /* 0 */  "63", "7c", "77", "7b", "f2", "6b", "6f", "c5", "30", "01", "67", "2b", "fe", "d7", "ab", "76",
        /* 1 */  "ca", "82", "c9", "7d", "fa", "59", "47", "f0", "ad", "d4", "a2", "af", "9c", "a4", "72", "c0",
        /* 2 */  "b7", "fd", "93", "26", "36", "3f", "f7", "cc", "34", "a5", "e5", "f1", "71", "d8", "31", "15",
        /* 3 */  "04", "c7", "23", "c3", "18", "96", "05", "9a", "07", "12", "80", "e2", "eb", "27", "b2", "75",
        /* 4 */  "09", "83", "2c", "1a", "1b", "6e", "5a", "a0", "52", "3b", "d6", "b3", "29", "e3", "2f", "84",
        /* 5 */  "53", "d1", "00", "ed", "20", "fc", "b1", "5b", "6a", "cb", "be", "39", "4a", "4c", "58", "cf",
        /* 6 */  "d0", "ef", "aa", "fb", "43", "4d", "33", "85", "45", "f9", "02", "7f", "50", "3c", "9f", "a8",
        /* 7 */  "51", "a3", "40", "8f", "92", "9d", "38", "f5", "bc", "b6", "da", "21", "10", "ff", "f3", "d2",
        /* 8 */  "cd", "0c", "13", "ec", "5f", "97", "44", "17", "c4", "a7", "7e", "3d", "64", "5d", "19", "73",
        /* 9 */  "60", "81", "4f", "dc", "22", "2a", "90", "88", "46", "ee", "b8", "14", "de", "5e", "0b", "db",
        /* a */  "e0", "32", "3a", "0a", "49", "06", "24", "5c", "c2", "d3", "ac", "62", "91", "95", "e4", "79",
        /* b */  "e7", "c8", "37", "6d", "8d", "d5", "4e", "a9", "6c", "56", "f4", "ea", "65", "7a", "ae", "08",
        /* c */  "ba", "78", "25", "2e", "1c", "a6", "b4", "c6", "e8", "dd", "74", "1f", "4b", "bd", "8b", "8a",
        /* d */  "70", "3e", "b5", "66", "48", "03", "f6", "0e", "61", "35", "57", "b9", "86", "c1", "1d", "9e",
        /* e */  "e1", "f8", "98", "11", "69", "d9", "8e", "94", "9b", "1e", "87", "e9", "ce", "55", "28", "df",
        /* f */  "8c", "a1", "89", "0d", "bf", "e6", "42", "68", "41", "99", "2d", "0f", "b0", "54", "bb", "16",};
    
    // Subsitution table for decryption (inverse of subsitution table for encryption)
    private final static String[] sBoxDecrypt = {
        /*          0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f */
        /* 0 */ "52", "09", "6a", "d5", "30", "36", "a5", "38", "bf", "40", "a3", "9e", "81", "f3", "d7", "fb",
        /* 1 */ "7c", "e3", "39", "82", "9b", "2f", "ff", "87", "34", "8e", "43", "44", "c4", "de", "e9", "cb",
        /* 2 */ "54", "7b", "94", "32", "a6", "c2", "23", "3d", "ee", "4c", "95", "0b", "42", "fa", "c3", "4e",
        /* 3 */ "08", "2e", "a1", "66", "28", "d9", "24", "b2", "76", "5b", "a2", "49", "6d", "8b", "d1", "25",
        /* 4 */ "72", "f8", "f6", "64", "86", "68", "98", "16", "d4", "a4", "5c", "cc", "5d", "65", "b6", "92",
        /* 5 */ "6c", "70", "48", "50", "fd", "ed", "b9", "da", "5e", "15", "46", "57", "a7", "8d", "9d", "84",
        /* 6 */ "90", "d8", "ab", "00", "8c", "bc", "d3", "0a", "f7", "e4", "58", "05", "b8", "b3", "45", "06",
        /* 7 */ "d0", "2c", "1e", "8f", "ca", "3f", "0f", "02", "c1", "af", "bd", "03", "01", "13", "8a", "6b",
        /* 8 */ "3a", "91", "11", "41", "4f", "67", "dc", "ea", "97", "f2", "cf", "ce", "f0", "b4", "e6", "73",
        /* 9 */ "96", "ac", "74", "22", "e7", "ad", "35", "85", "e2", "f9", "37", "e8", "1c", "75", "df", "6e",
        /* a */ "47", "f1", "1a", "71", "1d", "29", "c5", "89", "6f", "b7", "62", "0e", "aa", "18", "be", "1b",
        /* b */ "fc", "56", "3e", "4b", "c6", "d2", "79", "20", "9a", "db", "c0", "fe", "78", "cd", "5a", "f4",
        /* c */ "1f", "dd", "a8", "33", "88", "07", "c7", "31", "b1", "12", "10", "59", "27", "80", "ec", "5f",
        /* d */ "60", "51", "7f", "a9", "19", "b5", "4a", "0d", "2d", "e5", "7a", "9f", "93", "c9", "9c", "ef",
        /* e */ "a0", "e0", "3b", "4d", "ae", "2a", "f5", "b0", "c8", "eb", "bb", "3c", "83", "53", "99", "61",
        /* f */ "17", "2b", "04", "7e", "ba", "77", "d6", "26", "e1", "69", "14", "63", "55", "21", "0c", "7d",};
    
    // Round constants
    private final static String[] rConTable = 
        {"00", "01", "02", "04", "08", "10", "20", "40", "80", "1B", "36"};
    
    // Converts a string of text into its eqivalent binary representation (8-bits per char)
    public static String textToBinary(String text) {
        char[] characters = text.toCharArray();
        StringBuilder binary = new StringBuilder();
        
        for (int i = 0; i < characters.length; i++) {
            binary.append(String.format("%8s",Integer.toBinaryString(characters[i])).replaceAll(" ", "0"));
        }
        
        return binary.toString();
    }
    
    // Converts an integer, num, into its eqivalent [len]-bit binary representation
    public static String intToBinary(int num, int len) {
        StringBuilder binary = new StringBuilder(Integer.toBinaryString(num));
        
        while (binary.length() < len) 
            binary.insert(0, '0');
        
        return binary.toString();
    }
    
    // Converts a 2 character hex number into a 8-bit binary string
    public static String hex2ToBinary8(String hex) {
        int i = Integer.parseInt(hex, 16);
        StringBuilder binary = new StringBuilder(Integer.toBinaryString(i));
        
        while (binary.length() < 8)
            binary.insert(0, '0');
        
        return binary.toString();
    }
    
    // Converts a binary stream into its equivalent human readable text
    public static String binaryToText(String binary) {
        StringBuilder text = new StringBuilder();
        
        Arrays.stream(binary.split("(?<=\\G.{8})")).forEach(s -> text.append((char) Integer.parseInt(s, 2)));
        
        return text.toString();
    }
    
    // Converts a String array into a string
    public static String stringArrayToString (String[] stringArray) {
        StringBuilder str = new StringBuilder();
        
        for (int i = 0; i < stringArray.length; i++)
            str.append(stringArray[i]);
        
        return str.toString();
    }
    
    // XORs the bits of two binary strings of equal length
    public static String xorStrings(String binary1, String binary2) {
        StringBuilder result = new StringBuilder();
        
        if (binary1.length() != binary2.length()) {
            System.out.println("ERROR: Binary strings passed to xorStrings are not the same length.");
            System.out.printf("Binary 1 length: %d\nBinary 2 length: %d\n", binary1.length(), binary2.length());
        }
        else {
            for (int i = 0; i < binary1.length(); i++) {
                if (binary1.charAt(i) == binary2.charAt(i))
                    result.append("0");
                else
                    result.append("1");
            }
        }            
        
        return result.toString();
    }
    
    // Performs a bitwise & on two binary strings
    public static String bitwiseAndBinaryStrings(String binaryA, String binaryB) {
        StringBuilder result = new StringBuilder();
        
        if (binaryA.length() != binaryB.length()) {
            System.out.println("ERROR: Binary strings passed to bitwiseAndBinaryStrings are not the same length.");
            System.out.printf("Binary 1 length: %d\nBinary 2 length: %d\n", binaryA.length(), binaryB.length());
        }
        else {
            for (int i = 0; i < binaryA.length(); i++) {
                if (binaryA.charAt(i) == '1' && binaryB.charAt(i)== '1')
                    result.append("1");
                else
                    result.append("0");
            }
        }
        
        return result.toString();
    }
    
    // Shifts binary string a specified number of bits to the left. Discard leftmost bit and add a 0 bit on right
    public static String leftShift(String binary, int numOfShifts) {
        StringBuilder shiftedBinary = new StringBuilder();
        
        // for each shift
        for (int i = 0; i < numOfShifts; i++) {
            // shift all the bits to the left by one
            for (int j = 1; j < binary.length(); j++) 
                shiftedBinary.append(binary.charAt(j));
            shiftedBinary.append('0');
            binary = shiftedBinary.toString();
            shiftedBinary.setLength(0);
        }
        
        return binary;
    }
    
    // Shifts binary string a specified number of bits to the right. Discard rightmost bit and add a 0 bit on left
    public static String rightShift(String binary, int numOfShifts) {
        StringBuilder shiftedBinary = new StringBuilder();
        
        // for each shift
        for (int i = 0; i < numOfShifts; i++) {
            // shift all the bits to the right by one
            shiftedBinary.append('0');
            for (int j = 0; j < binary.length()-1; j++) 
                shiftedBinary.append(binary.charAt(j));
            
            binary = shiftedBinary.toString();
            shiftedBinary.setLength(0);
        }
        
        return binary;
    }
    
    // Converts a multi-byte binary string into an array of binary string bytes
    public static String[] binaryToBytes(String binary) {
        if (binary.length() % 8 != 0) {
            String [] error = {"ERROR: Binary passed to binaryToBytes is not a multiple of 8"};
            return error;
        }
        else {
            String [] bytes = new String[binary.length()/8];
            for (int i = 0; i < bytes.length; i++) {
                bytes[i] = binary.substring(i*8, (i+1)*8);
            }
            return bytes;
        }
    }
    
    // Converts a binary string into an array of binary string 4-byte words
    // This is often used to get the columns of a 128-bit binary arranged in column-major order
    public static String[] binaryToWords(String binary) {
        if (binary.length() % 32 != 0) {
            String [] error = {"ERROR: Binary passed to binaryToWords is not a multiple of 32"};
            return error;
        }
        else {
            String [] words = new String[binary.length()/32];
            for (int i = 0; i < words.length; i++) {
                words[i] = binary.substring(i*32, (i+1)*32);
            }
            return words;
        }
    }
    
    // Splits textBinary into 128-bit blocks, padding at end
    public static String[] blockTextPad128(String textBinary) {
        int numOfBlocks = textBinary.length()/128 + 1; // +1 to account for remainder
        String[] textBinaryBlocks = new String[numOfBlocks];
        StringBuilder textBinaryBlock = new StringBuilder();
        
        for (int i = 0; i < numOfBlocks-1; i++) {
            textBinaryBlock.append(textBinary.substring(i*128, (i+1)*128));
            textBinaryBlocks[i] = textBinaryBlock.toString();
            textBinaryBlock.setLength(0);
        }
        
        if (textBinary.length() % 128 == 0)
            textBinaryBlock.append("1000000000000000000000000000000000000000000000000000000000000000");
        else {
            String temp = textBinary.substring((numOfBlocks-1)*128);
            textBinaryBlock.append(temp);
            textBinaryBlock.append("1");
            int numOf0s = 128 - temp.length() - 1;
            for (int i = 0; i < numOf0s; i++)
                textBinaryBlock.append("0");
        }
        textBinaryBlocks[numOfBlocks-1] = textBinaryBlock.toString();
        
        return textBinaryBlocks;
    }
    
    // Splits textBinary into 128-bit blocks, assumes input is already padded to be divisible by 128
    public static String[] blockText128(String textBinary) {
        int numOfBlocks = textBinary.length()/128; 
        String[] textBinaryBlocks = new String[numOfBlocks];
        StringBuilder textBinaryBlock = new StringBuilder();
        
        for (int i = 0; i < numOfBlocks; i++) {
            textBinaryBlock.append(textBinary.substring(i*128, (i+1)*128));
            textBinaryBlocks[i] = textBinaryBlock.toString();
            textBinaryBlock.setLength(0);
        }
        
        return textBinaryBlocks;
    }
    
    // Removes the padding at the end of a string
    public static String removePad(String textBinary) {
        boolean padStartFound = false;
        int index = textBinary.length() - 1;
        
        while(!padStartFound) {
            if (textBinary.charAt(index) == '1')
                padStartFound = true;
            else if (textBinary.charAt(index) == '0')
                index--;
            else {
                System.out.println("ERROR: Text binary passed to removePad is not a binary.");
                padStartFound = true;
            }
        }
        
        textBinary = textBinary.substring(0, index);
        
        return textBinary;
    }
    
    // Generates a 128, 192, or 256-bit key binary
    public static String generateKey(int bitLength) {
        StringBuilder key = new StringBuilder();
        Random rand = new Random();
        int i, r;
        
        if (bitLength == 128 || bitLength == 192 || bitLength == 256) {
            for (i = 0; i < bitLength; i++) {
                r = rand.nextInt(2);
                key.append(String.valueOf(r));
            }
        }
        else
            return "\nERROR: AES key must be 128, 192, or 256 bits long";
        
        return key.toString();
    }
    
    // Circularly rotates each byte in a 4-byte word to the left
    public static String rotWord(String binaryWord) {
        String[] bytes = binaryToBytes(binaryWord);
        if (bytes.length != 4)
             System.out.println("ERROR: Binary word passed to rotWord was not 4 bytes");
        
        String temp = bytes[0];
        
        bytes[0] = bytes[1];
        bytes[1] = bytes[2];
        bytes[2] = bytes[3];
        bytes[3] = temp;
        
        return stringArrayToString(bytes);
    }
    
    // Swaps a byte witht the corresponding byte in the subsitution table
    public static String subByte(String iBinary8, String[] sBox) {
        String fHex = sBox[Integer.parseInt(iBinary8, 2)];
        return hex2ToBinary8(fHex);
    }
    
    // Swaps bytes in a 4-byte word with the the corresponding bytes in the subsitution table
    public static String subWord(String binaryWord, String[] sBox) {
         String[] bytes = binaryToBytes(binaryWord);
         if (bytes.length != 4)
             System.out.println("ERROR: Binary word passed to subWord was not 4 bytes");
         
         for (int i = 0; i < 4; i++) 
             bytes[i] = subByte(bytes[i], sBox);
         
         return stringArrayToString(bytes);
    }
    
    // XORs the first byte of the 4-byte word with a round constant 
    // (just the first byte of rCon since the other bytes in the word would be 00)
    public static String rCon(String binaryWord, int round) {
        String[] bytes = binaryToBytes(binaryWord);
        bytes[0] = xorStrings(bytes[0], hex2ToBinary8(rConTable[round]));
        
        return stringArrayToString(bytes);
    }
        
    // Generates a set of round keys, called the key schedule, from a 128-bit key
    public static String[] generateKeySchedule128(String key) {
        String[] keySchedule = new String[11];
        String[] words = binaryToWords(key);
        StringBuilder tempWord = new StringBuilder();
        
        if (words.length != 4) {
            String [] error = {"ERROR: Key contains more than 4 32-bit words"};
            return error;
        }
        else {
            keySchedule[0] = key;
            for (int i = 1; i < 11; i++) {
                tempWord.append(rotWord(words[3]));
                tempWord.replace(0, tempWord.length(), subWord(tempWord.toString(), sBoxEncrypt));
                tempWord.replace(0, tempWord.length(), rCon(tempWord.toString(), i));
                
                words[0] = xorStrings(tempWord.toString(), words[0]);
                words[1] = xorStrings(words[0], words[1]);
                words[2] = xorStrings(words[1], words[2]);
                words[3] = xorStrings(words[2], words[3]);
                
                tempWord.setLength(0);
                
                keySchedule[i] = stringArrayToString(words);
            }

            return keySchedule;
        }
    }
    
    // Swap bytes in a 128-bit binary string with the corresponding bytes in the subsitution table
    public static String substitute128(String binary128, String[] sBox) {
        String[] bytes = binaryToBytes(binary128);
         if (bytes.length != 16)
             System.out.println("ERROR: Binary passed to substitute128 was not 16 bytes");
         
         for (int i = 0; i < 16; i++) 
             bytes[i] = subByte(bytes[i], sBox);
         
         return stringArrayToString(bytes);
    }
    
    // Left circular shift the second row by 1, third row by 2, and fourth row by 3
    // Input is a 128-bit binary arranged in column-major order
    public static String shiftRows(String binary128) {
        String[] bytes = binaryToBytes(binary128);
        
        // Left circular shift the second row by 1
        String temp = bytes[1];
        bytes[1] = bytes[5];
        bytes[5] = bytes[9];
        bytes[9] = bytes[13];
        bytes[13] = temp;
        
        // Left circular shift the third row by 2
        temp = bytes[2];
        bytes[2] = bytes[10];
        bytes[10] = temp;
        temp = bytes[6];
        bytes[6] = bytes[14];
        bytes[14] = temp;
        
        // Left circular shift the fourth row by 3
        temp = bytes[3];
        bytes[3] = bytes[15];
        bytes[15] = bytes[11];
        bytes[11] = bytes[7];
        bytes[7] = temp;
        
        return stringArrayToString(bytes);
    }
    
    // Galois field (a finite field) multiplication of two 8-bit binaries
    public static String GFMult(String binaryAString, String binaryBString) {
        StringBuilder binaryA = new StringBuilder(binaryAString);
        StringBuilder binaryB = new StringBuilder(binaryBString);
        StringBuilder result = new StringBuilder("00000000");
        StringBuilder shiftGreaterThan255 = new StringBuilder("00000000");
        
        // Loops through each bit
        for (int i = 0; i < 8; i++) {
            if (bitwiseAndBinaryStrings(binaryB.toString(), "00000001").equals("00000001"))
                result.replace(0, result.length(), xorStrings(result.toString(), binaryA.toString()));
            
            shiftGreaterThan255.replace(0, shiftGreaterThan255.length(), bitwiseAndBinaryStrings(binaryA.toString(), "10000000"));
            binaryA.replace(0, binaryA.length(), leftShift(binaryA.toString(), 1));
        
            if (shiftGreaterThan255.toString().equals("10000000"))
                binaryA.replace(0, binaryA.length(), xorStrings(binaryA.toString(), "00011011"));
        
            binaryB.replace(0, binaryB.length(), rightShift(binaryB.toString(), 1));
        }
        
        return result.toString();
    }
    
    // Mixes the elements of the column
    public static String mixColumn(String column32) {
        String[] column = binaryToBytes(column32);
        String[] mixedColumn = new String[4];
        StringBuilder tempA = new StringBuilder();
        StringBuilder tempB = new StringBuilder();
        
        tempA.append(GFMult("00000010", column[0]));
        tempB.append(GFMult("00000011", column[1]));
        tempA.replace(0, tempA.length(), xorStrings(tempA.toString(), tempB.toString()));
        tempA.replace(0, tempA.length(), xorStrings(tempA.toString(), column[2]));
        tempA.replace(0, tempA.length(), xorStrings(tempA.toString(), column[3]));
        mixedColumn[0] = tempA.toString();
        tempA.setLength(0);
        tempB.setLength(0);
        
        tempA.append(column[0]);
        tempB.append(GFMult("00000010", column[1]));
        tempA.replace(0, tempA.length(), xorStrings(tempA.toString(), tempB.toString()));
        tempB.replace(0, tempB.length(), GFMult("00000011", column[2]));
        tempA.replace(0, tempA.length(), xorStrings(tempA.toString(), tempB.toString()));
        tempA.replace(0, tempA.length(), xorStrings(tempA.toString(), column[3]));
        mixedColumn[1] = tempA.toString();
        tempA.setLength(0);
        tempB.setLength(0);
        
        tempA.append(column[0]);
        tempA.replace(0, tempA.length(), xorStrings(tempA.toString(), column[1]));
        tempB.append(GFMult("00000010", column[2]));
        tempA.replace(0, tempA.length(), xorStrings(tempA.toString(), tempB.toString()));
        tempB.replace(0, tempB.length(), GFMult("00000011", column[3]));
        tempA.replace(0, tempA.length(), xorStrings(tempA.toString(), tempB.toString()));
        mixedColumn[2] = tempA.toString();
        tempA.setLength(0);
        tempB.setLength(0);
        
        tempA.append(GFMult("00000011", column[0]));
        tempA.replace(0, tempA.length(), xorStrings(tempA.toString(), column[1]));
        tempA.replace(0, tempA.length(), xorStrings(tempA.toString(), column[2]));
        tempB.append(GFMult("00000010", column[3]));
        tempA.replace(0, tempA.length(), xorStrings(tempA.toString(), tempB.toString()));
        mixedColumn[3] = tempA.toString();
        
        return stringArrayToString(mixedColumn);
    }
    
    // Mixes the elements of the columns in the current block to provide diffusion
    public static String mixColumns(String binary128) {
        String[] columns = binaryToWords(binary128);
        String[] mixedColumns = new String[4];
        
        for (int i = 0; i < 4; i++)
            mixedColumns[i] = mixColumn(columns[i]);
        
        return stringArrayToString(mixedColumns);
    }
    
    // Encrypts a 128-bit plaintext block using the key schedule 
    public static String encryptBlock(String plainBinaryBlockString, String[] keySchedule) {
        System.out.printf("\tInput binary block: %s\n", plainBinaryBlockString);
        
        StringBuilder binaryBlock = new StringBuilder();
        
        // XOR the plaintext binary block with the origional secret key (the first round key in the key scheudle
        binaryBlock.append(xorStrings(plainBinaryBlockString, keySchedule[0]));
        System.out.printf("\tXOR with origional key: %s\n", binaryBlock);
        
        // 10 rounds of encryption because 128-bit key
        for (int i = 0; i < 10; i++) {
            // Substitute bytes
            binaryBlock.replace(0, binaryBlock.length(), substitute128(binaryBlock.toString(), sBoxEncrypt));
            
            // Shift rows
            binaryBlock.replace(0, binaryBlock.length(), shiftRows(binaryBlock.toString()));
            
            // Mix columns, skip if last round
            if (i != 9)
                binaryBlock.replace(0, binaryBlock.length(), mixColumns(binaryBlock.toString()));

            // XOR (add) the round key
            binaryBlock.replace(0, binaryBlock.length(), xorStrings(binaryBlock.toString(), keySchedule[i+1]));
            
            System.out.printf("\tRound %d: %s\n", i + 1, binaryBlock);
        }
                
        return binaryBlock.toString();
    }
    
    // Encrypts the plaintext with the key to produce a ciphertext
    public static String encrypt(String plaintext, String key) {
        // Convert plaintext to its binary representation
        StringBuilder plainBinary = new StringBuilder(textToBinary(plaintext));
        System.out.printf("\tPlaintext binary: %s\n", plainBinary);
        
        // Generate key schedule
        String[] keySchedule = generateKeySchedule128(key);
        
        System.out.println("\tKey schedule: ");
        for (int i = 0; i < keySchedule.length; i++) 
            System.out.printf("\t\t %d: %s\n", i, keySchedule[i]);
        System.out.println("");
        
        // Split the plaintext binary into plaintext binary blocks, add padding
        String[] plainBinaryBlocks = blockTextPad128(plainBinary.toString());
        
        // Encrypt each plaintext binary block
        String[] cipherBinaryBlocks = new String[plainBinaryBlocks.length];
        for (int i = 0; i < plainBinaryBlocks.length; i++) {
            System.out.printf("Encrypting block %d:\n", i+1);
            cipherBinaryBlocks[i] = encryptBlock(plainBinaryBlocks[i], keySchedule);
        }

        // Put ciphertext binary blocks together
        String cipherBinary = stringArrayToString(cipherBinaryBlocks);
        System.out.printf("\nCiphertext binary: %s\n", cipherBinary);
        
        // Convert ciphertext binary into ciphertext
        String ciphertext = binaryToText(cipherBinary);
        return ciphertext;
    }
    
    // Mixes the elements of the column, inverse to origional
    public static String invMixColumn(String column32) {
        String[] column = binaryToBytes(column32);
        String[] mixedColumn = new String[4];
        StringBuilder tempA = new StringBuilder();
        StringBuilder tempB = new StringBuilder();
        
        // 0x09 = 00001001
        // 0x0d = 00001101
        // 0x0e = 00001110
        // 0x0b = 00001011
        
        tempA.append(GFMult("00001110", column[0]));
        tempB.append(GFMult("00001011", column[1]));
        tempA.replace(0, tempA.length(), xorStrings(tempA.toString(), tempB.toString()));
        tempB.replace(0, tempB.length(), GFMult("00001101", column[2]));
        tempA.replace(0, tempA.length(), xorStrings(tempA.toString(), tempB.toString()));
        tempB.replace(0, tempB.length(), GFMult("00001001", column[3]));
        tempA.replace(0, tempA.length(), xorStrings(tempA.toString(), tempB.toString()));
        mixedColumn[0] = tempA.toString();
        tempA.setLength(0);
        tempB.setLength(0);
        
        tempA.append(GFMult("00001001", column[0]));
        tempB.append(GFMult("00001110", column[1]));
        tempA.replace(0, tempA.length(), xorStrings(tempA.toString(), tempB.toString()));
        tempB.replace(0, tempB.length(), GFMult("00001011", column[2]));
        tempA.replace(0, tempA.length(), xorStrings(tempA.toString(), tempB.toString()));
        tempB.replace(0, tempB.length(), GFMult("00001101", column[3]));
        tempA.replace(0, tempA.length(), xorStrings(tempA.toString(), tempB.toString()));
        mixedColumn[1] = tempA.toString();
        tempA.setLength(0);
        tempB.setLength(0);
        
        tempA.append(GFMult("00001101", column[0]));
        tempB.append(GFMult("00001001", column[1]));
        tempA.replace(0, tempA.length(), xorStrings(tempA.toString(), tempB.toString()));
        tempB.replace(0, tempB.length(), GFMult("00001110", column[2]));
        tempA.replace(0, tempA.length(), xorStrings(tempA.toString(), tempB.toString()));
        tempB.replace(0, tempB.length(), GFMult("00001011", column[3]));
        tempA.replace(0, tempA.length(), xorStrings(tempA.toString(), tempB.toString()));
        mixedColumn[2] = tempA.toString();
        tempA.setLength(0);
        tempB.setLength(0);
        
        tempA.append(GFMult("00001011", column[0]));
        tempB.append(GFMult("00001101", column[1]));
        tempA.replace(0, tempA.length(), xorStrings(tempA.toString(), tempB.toString()));
        tempB.replace(0, tempB.length(), GFMult("00001001", column[2]));
        tempA.replace(0, tempA.length(), xorStrings(tempA.toString(), tempB.toString()));
        tempB.replace(0, tempB.length(), GFMult("00001110", column[3]));
        tempA.replace(0, tempA.length(), xorStrings(tempA.toString(), tempB.toString()));
        mixedColumn[3] = tempA.toString();
        
        return stringArrayToString(mixedColumn);
    }
    
    // Mixes the elements of the columns in the current block, inverse to origional
    public static String invMixColumns(String binary128) {
        String[] columns = binaryToWords(binary128);
        String[] mixedColumns = new String[4];
        
        for (int i = 0; i < 4; i++)
            mixedColumns[i] = invMixColumn(columns[i]);
        
        return stringArrayToString(mixedColumns);
    }
    
    // Right circular shift the second row by 1, third row by 2, and fourth row by 3
    // Input is a 128-bit binary arranged in column-major order
    public static String invShiftRows(String binary128) {
        String[] bytes = binaryToBytes(binary128);
        
        // Right circular shift the second row by 1
        String temp = bytes[1];
        bytes[1] = bytes[13];
        bytes[13] = bytes[9];
        bytes[9] = bytes[5];
        bytes[5] = temp;
        
        // Right circular shift the third row by 2
        temp = bytes[2];
        bytes[2] = bytes[10];
        bytes[10] = temp;
        temp = bytes[6];
        bytes[6] = bytes[14];
        bytes[14] = temp;
        
        // Right circular shift the fourth row by 3
        temp = bytes[3];
        bytes[3] = bytes[7];
        bytes[7] = bytes[11];
        bytes[11] = bytes[15];
        bytes[15] = temp;
        
        return stringArrayToString(bytes);
    }
    
    // Decrypts a 128-bit ciphertext block using the key schedule 
    public static String decryptBlock(String cipherBinaryBlockString, String[] keySchedule) {
        System.out.printf("\tInput binary block: %s\n", cipherBinaryBlockString);
        
        StringBuilder binaryBlock = new StringBuilder(cipherBinaryBlockString);
        
        // 10 rounds of decryption because 128-bit key, decrementing to go backwards through the key schedule
        for (int i = 9; i >= 0; i--) {
            // XOR (add) the round key
            binaryBlock.replace(0, binaryBlock.length(), xorStrings(binaryBlock.toString(), keySchedule[i+1]));
            
            // Inverse Mix columns, skip if first round
            if (i != 9)
                binaryBlock.replace(0, binaryBlock.length(), invMixColumns(binaryBlock.toString()));
            
            // Inverse shift rows
            binaryBlock.replace(0, binaryBlock.length(), invShiftRows(binaryBlock.toString()));
            
            // Substitute bytes
            binaryBlock.replace(0, binaryBlock.length(), substitute128(binaryBlock.toString(), sBoxDecrypt));
            
            System.out.printf("\tRound %d: %s\n", i + 1, binaryBlock);
        }
        
        // XOR the binary block with the origional secret key (the first round key in the key scheudle
        binaryBlock.replace(0, binaryBlock.length(), xorStrings(binaryBlock.toString(), keySchedule[0]));
        System.out.printf("\tXOR with origional key: %s\n", binaryBlock);
                
        return binaryBlock.toString();
    }
    
    // Decrypts the ciphertext with the key to produce the plaintext
    public static String decrypt(String ciphertext, String key) {
        // Convert ciphertext to its binary representation
        StringBuilder cipherBinary = new StringBuilder(textToBinary(ciphertext));
        System.out.printf("\tCiphertext binary: %s\n", cipherBinary);
        
        // Generate key schedule
        String[] keySchedule = generateKeySchedule128(key);
        
        System.out.println("\tKey schedule: ");
        for (int i = 0; i < keySchedule.length; i++) 
            System.out.printf("\t\t %d: %s\n", i, keySchedule[i]);
        System.out.println("");
        
        // Split the ciphertext binary into ciphertext binary blocks, no padding
        String[] cipherBinaryBlocks = blockText128(cipherBinary.toString());
        
        // Decrypt each ciphertext binary block
        String[] plainBinaryBlocks = new String[cipherBinaryBlocks.length];
        for (int i = 0; i < cipherBinaryBlocks.length; i++) {
            System.out.printf("Decrypting block %d:\n", i+1);
            plainBinaryBlocks[i] = decryptBlock(cipherBinaryBlocks[i], keySchedule);
        }

        // Put plaintext binary blocks together
        String plainBinary = stringArrayToString(plainBinaryBlocks);
        System.out.printf("\nPlaintext binary with padding: %s\n", plainBinary);
        
        // Remove padding
        plainBinary = removePad(plainBinary);
        System.out.printf("Plaintext binary: %s\n", plainBinary);
        
        // Convert plaintext binary into plaintext
        String plaintext = binaryToText(plainBinary);
        return plaintext;
    }

    public static void main(String[] args) {
        System.out.println("AES implementation demonstration: \n");
        
        String plaintext = "Hello World! It's a nice day.";
        System.out.printf("Plaintext: %s\n\n", plaintext);
        
        String key128 = generateKey(128);
        System.out.printf("New 128-bit key: %s\n\n", key128);
        
        System.out.println("Begin encryption: ");
        String ciphertext = encrypt(plaintext, key128);
        System.out.printf("Ciphertext: %s\n\n", ciphertext);

        System.out.println("Begin decryption: ");
        String decryptedtext = decrypt(ciphertext, key128);
        System.out.printf("Decrypted text = %s\n\n", decryptedtext);
        
        // Test to see if it worked
        if (plaintext.equals(decryptedtext))
            System.out.println("Success!\n");
        else
            System.out.println("Failure.\n");    
        
    }
}
