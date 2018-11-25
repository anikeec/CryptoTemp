package com.apu.cryptotemp;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.engines.GOST28147Engine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.*;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;

public class GOST28147Encription {

    public String Encode(String str, byte[] key) {
        return processEncoding(true, str, key);
    }

    public byte[] Encode(byte[] str, byte[] key) {
        return processEncoding(true, str, key);
    }
    
    public byte[] EncodeWithoutPadding(byte[] str, byte[] key) {
        return processEncodingWithoutPadding(true, str, key);
    }
    
    public byte[] EncodeZeroPadding(byte[] str, byte[] key) {
        return processEncodingZeroPadding(true, str, key);
    }
    
    public String Decode(String str, byte[] key) {
        return processEncoding(false, str, key);
    }

    public byte[] Decode(byte[] str, byte[] key) {
        return processEncoding(false, str, key);
    }
    
    public byte[] DecodeWithoutPadding(byte[] str, byte[] key) {
        return processEncodingWithoutPadding(false, str, key);
    }
    
    public byte[] DecodeZeroPadding(byte[] str, byte[] key) {
        return processEncodingZeroPadding(false, str, key);
    }
    
    public String Decode(String str, byte[] key, int length) {
        return processEncoding(false, str, key, length);
    }

    public byte[] Decode(byte[] str, byte[] key, int length) {
        return trimBytes(processEncoding(false, str, key), length);
    }

    public String processEncoding(boolean ende, String str, byte[] key) {
        byte[] bytes = processEncoding(ende, str.getBytes(), key);//Hex.encode(str.getBytes())
        return new String(bytes);//Hex.decode(bytes)
    }

    public String processEncoding(boolean ende, String str, byte[] key, int length) {
        byte[] bytes = trimBytes(processEncoding(ende, str.getBytes(), key), length);//Hex.encode(str.getBytes())
        return new String(bytes);//Hex.decode(bytes)
    }

    public byte[] processEncodingWithoutPadding(boolean ende, byte[] inBytes, byte[] key) {
        CBCBlockCipher cipher = new CBCBlockCipher(
                new GOST28147Engine());
        cipher.init(ende, new KeyParameter(key));

        int blocksAmount = inBytes.length/cipher.getBlockSize();
        if(inBytes.length % cipher.getBlockSize() != 0)
            blocksAmount++;
        int blockSize = cipher.getBlockSize();
        
        byte[] outBytes = new byte[blocksAmount * blockSize];
        
        int inOffset = 0;
        int outOffset = 0;
        
        for(int blockId=0; blockId<blocksAmount; blockId++) {
            inOffset = blockId * blockSize;
            outOffset = inOffset;
            cipher.processBlock(inBytes, inOffset, outBytes, outOffset);
        }
//        int len = cipher.processBytes(inBytes, 0, inBytes.length, outBytes, 0);
//        try {
//            cipher.doFinal(outBytes, len);
//        } catch (CryptoException e) {
//            System.out.println("Exception: " + e.toString());
//        }
        return outBytes;
    }
    
    public byte[] processEncodingZeroPadding(boolean ende, byte[] inBytes, byte[] key) {
        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(
                new GOST28147Engine()), new ZeroBytePadding());
        cipher.init(ende, new KeyParameter(key));
        byte[] outBytes = new byte[cipher.getOutputSize(inBytes.length)];
        int len = cipher.processBytes(inBytes, 0, inBytes.length, outBytes, 0);
        try {
            cipher.doFinal(outBytes, len);
        } catch (CryptoException e) {
            System.out.println("Exception: " + e.toString());
        }
        return outBytes;
    }
    
    public byte[] processEncoding(boolean ende, byte[] inBytes, byte[] key) {
        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(
                new GOST28147Engine()));
        cipher.init(ende, new KeyParameter(key));
        byte[] outBytes = new byte[cipher.getOutputSize(inBytes.length)];
        int len = cipher.processBytes(inBytes, 0, inBytes.length, outBytes, 0);
        try {
            cipher.doFinal(outBytes, len);
        } catch (CryptoException e) {
            System.out.println("Exception: " + e.toString());
        }
        return outBytes;
    }

    public byte[] trimBytes(byte[] bytes, int length) {
        byte[] outBytesTrimmed = new byte[length];
        for (int i = 0; i < length; i++) {
            outBytesTrimmed[i] = bytes[i];
        }
        return outBytesTrimmed;
    }
    
}
