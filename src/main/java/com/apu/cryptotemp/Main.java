package com.apu.cryptotemp;

public class Main {
    
    public static void main(String[] args) {
        
        byte[] key = "Secret 32 bytes key for encrypt.".getBytes();
//        byte[] key =  new byte[]{
//                                (byte)0xFE, (byte)0xDC, (byte)0xBA, (byte)0x98, (byte)0x76, (byte)0x54, 
//                                (byte)0x32, (byte)0x10, (byte)0xFE, (byte)0xDC, (byte)0xBA, (byte)0x98,
//                                (byte)0x76, (byte)0x54, (byte)0x32, (byte)0x10, (byte)0xFE, (byte)0xDC,
//                                (byte)0xBA, (byte)0x98, (byte)0x76, (byte)0x54, (byte)0x32, (byte)0x10,
//                                (byte)0xFE, (byte)0xDC, (byte)0xBA, (byte)0x98, (byte)0x76, (byte)0x54,
//                                (byte)0x32, (byte)0x10
//                                };
    
        GOST28147Encription encriptor = new GOST28147Encription();

//        byte[] strBytes = new byte[] {
//                                (byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67, (byte)0x89, (byte)0xAB, 
//                                (byte)0xCD, (byte)0xEF};
        byte[] strBytes = "It is the string for encoding or trying new encription".getBytes();
        System.out.println(new String(strBytes));
        
        byte[] encodedBytes = encriptor.Encode(strBytes, key);
        System.out.println(new String(encodedBytes));
        
        byte[] decodedBytes = encriptor.Decode(encodedBytes, key);       
        System.out.println(new String(decodedBytes));
    }
    
}
