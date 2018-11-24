package com.apu.cryptotemp;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.engines.GOST28147Engine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;

public class GOST28147Encription {

    public String Encode(String str, byte[] key) {
        return processEncoding(true, str, key);
    }

    public byte[] Encode(byte[] str, byte[] key) {
        return processEncoding(true, str, key);
    }
    
    public String Decode(String str, byte[] key) {
        return processEncoding(false, str, key);
    }

    public byte[] Decode(byte[] str, byte[] key) {
        return processEncoding(false, str, key);
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