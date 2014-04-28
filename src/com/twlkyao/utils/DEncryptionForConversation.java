package com.twlkyao.utils;

import android.annotation.SuppressLint;
import java.io.IOException;  
import java.security.SecureRandom;  
import javax.crypto.Cipher;  
import javax.crypto.SecretKey;  
import javax.crypto.SecretKeyFactory;  
import javax.crypto.spec.DESKeySpec;  

public class DEncryptionForConversation {  
  
    @SuppressLint("TrulyRandom")
	public static byte[] desEncrypt(byte[] plainText, String skey) throws Exception {  
        SecureRandom sr = new SecureRandom();  
        byte rawKeyData[] = skey.getBytes();  
        DESKeySpec dks = new DESKeySpec(rawKeyData);  
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");  
        SecretKey key = keyFactory.generateSecret(dks);  
        Cipher cipher = Cipher.getInstance("DES");  
        cipher.init(Cipher.ENCRYPT_MODE, key, sr);  
        byte data[] = plainText;  
        byte encryptedData[] = cipher.doFinal(data);  
        return encryptedData;  
    }  
  
    public static byte[] desDecrypt(byte[] encryptText, String skey) throws Exception {  
        SecureRandom sr = new SecureRandom();  
        byte rawKeyData[] = skey.getBytes();  
        DESKeySpec dks = new DESKeySpec(rawKeyData);  
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");  
        SecretKey key = keyFactory.generateSecret(dks);  
        Cipher cipher = Cipher.getInstance("DES");  
        cipher.init(Cipher.DECRYPT_MODE, key, sr);  
        byte encryptedData[] = encryptText;  
        byte decryptedData[] = cipher.doFinal(encryptedData);  
        return decryptedData;  
    }   
  
    public static String conversationencrypt(String input, String key) throws Exception {  
        return base64Encode(desEncrypt(input.getBytes(),key));  
    }  
  
    public static String conversationdecrypt(String input, String key) throws Exception {  
        byte[] result = base64Decode(input);  
        return new String(desDecrypt(result, key));  
    }  
  
    public static String base64Encode(byte[] s) {  
        if (s == null)  
            return null;  
        return Base64Encoder.encode(s);  
    }  
  
    public static byte[] base64Decode(String s) throws IOException {  
        if (s == null)  
            return null;  
        byte[] b = Base64Decoder.decodeToBytes(s);  
        return b;  
    }  
}
