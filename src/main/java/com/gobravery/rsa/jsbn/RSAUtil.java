package com.gobravery.rsa.jsbn;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;  

/** 
 * RSA 工具类。提供加密，解密，生成密钥对等方法。 
 * 需要到  下载bcprov-jdk14-123.jar。 
 *  
 */  



public class RSAUtil {
    private static final int MAX_ENCRYPT_BLOCK = 117; // RSA最大加密明文大小
    private static final int MAX_DECRYPT_BLOCK = 128; // RSA最大解密密文大小

    /**
     * 生成公钥和私钥
     *
     * @throws NoSuchAlgorithmException
     */
    public static KeyPair genRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(1024);
        return keyPairGen.generateKeyPair();
    }

    /**
     * 使用模和指数生成RSA公钥
     * 注意：【此代码用了默认补位方式，为RSA/None/PKCS1Padding，不同JDK默认的补位方式可能不同，如Android默认是RSA
     * /None/NoPadding】
     *
     * @param modulus  模
     * @param exponent 指数
     * @return
     */
    public static RSAPublicKey getPublicKey(String modulus, String exponent) {
        try {
            BigInteger b1 = new BigInteger(modulus, 16);
            BigInteger b2 = new BigInteger(exponent, 16);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(b1, b2);
            return (RSAPublicKey) keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 使用模和指数生成RSA私钥
     * 注意：【此代码用了默认补位方式，为RSA/None/PKCS1Padding，不同JDK默认的补位方式可能不同，如Android默认是RSA
     * /None/NoPadding】
     *
     * @param modulus  模
     * @param exponent 指数
     * @return
     */
    public static RSAPrivateKey getPrivateKey(String modulus, String exponent) {
        try {
            BigInteger b1 = new BigInteger(modulus, 16);
            BigInteger b2 = new BigInteger(exponent, 16);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(b1, b2);
            return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 公钥加密
     */
    public static byte[] encryptByPublicKey(byte[] data, RSAPublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        int inputLen = data.length;

        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            int offSet = 0;
            byte[] cache;
            int i = 0;
            // 对数据分段加密
            while (inputLen - offSet > 0) {
                if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
                    cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);
                } else {
                    cache = cipher.doFinal(data, offSet, inputLen - offSet);
                }
                out.write(cache, 0, cache.length);
                i++;
                offSet = i * MAX_ENCRYPT_BLOCK;
            }
            return out.toByteArray();
        }
    }

    /**
     * 私钥解密
     */
    public static String decryptByPrivateKey(byte[] encryptedData, RSAPrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        int inputLen = encryptedData.length;

        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {

            int offSet = 0;
            byte[] cache;
            int i = 0;

            // 对数据分段解密
            while (inputLen - offSet > 0) {
                if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
                    cache = cipher.doFinal(encryptedData, offSet, MAX_DECRYPT_BLOCK);
                } else {
                    cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);
                }
                out.write(cache, 0, cache.length);
                i++;
                offSet = i * MAX_DECRYPT_BLOCK;
            }

            return new String(out.toByteArray(), "utf-8");
        }
    }

    /**
     * ASCII码转BCD码
     */
    public static byte[] ASCII_To_BCD(byte[] ascii, int asc_len) {
        byte[] bcd = new byte[asc_len / 2];
        int j = 0;
        for (int i = 0; i < (asc_len + 1) / 2; i++) {
            bcd[i] = asc_to_bcd(ascii[j++]);
            bcd[i] = (byte) (((j >= asc_len) ? 0x00 : asc_to_bcd(ascii[j++])) + (bcd[i] << 4));
        }
        return bcd;
    }

    public static byte asc_to_bcd(byte asc) {
        byte bcd;

        if ((asc >= '0') && (asc <= '9'))
            bcd = (byte) (asc - '0');
        else if ((asc >= 'A') && (asc <= 'F'))
            bcd = (byte) (asc - 'A' + 10);
        else if ((asc >= 'a') && (asc <= 'f'))
            bcd = (byte) (asc - 'a' + 10);
        else
            bcd = (byte) (asc - 48);
        return bcd;
    }

    /**
     * BCD转字符串
     */
    public static String bcd2Str(byte[] bytes) {
        char temp[] = new char[bytes.length * 2], val;

        for (int i = 0; i < bytes.length; i++) {
            val = (char) (((bytes[i] & 0xf0) >> 4) & 0x0f);
            temp[i * 2] = (char) (val > 9 ? val + 'A' - 10 : val + '0');

            val = (char) (bytes[i] & 0x0f);
            temp[i * 2 + 1] = (char) (val > 9 ? val + 'A' - 10 : val + '0');
        }
        return new String(temp);
    }

    /**
     * 拆分字符串
     */
    public static String[] splitString(String string, int len) {
        int x = string.length() / len;
        int y = string.length() % len;
        int z = 0;
        if (y != 0) {
            z = 1;
        }
        String[] strings = new String[x + z];
        String str = "";
        for (int i = 0; i < x + z; i++) {
            if (i == x + z - 1 && y != 0) {
                str = string.substring(i * len, i * len + y);
            } else {
                str = string.substring(i * len, i * len + len);
            }
            strings[i] = str;
        }
        return strings;
    }

    /**
     * 拆分数组
     */
    public static byte[][] splitArray(byte[] data, int len) {
        int x = data.length / len;
        int y = data.length % len;
        int z = 0;
        if (y != 0) {
            z = 1;
        }
        byte[][] arrays = new byte[x + z][];
        byte[] arr;
        for (int i = 0; i < x + z; i++) {
            arr = new byte[len];
            if (i == x + z - 1 && y != 0) {
                System.arraycopy(data, i * len, arr, 0, y);
            } else {
                System.arraycopy(data, i * len, arr, 0, len);
            }
            arrays[i] = arr;
        }
        return arrays;
    }
    //String 解密
 public static String Decrypt(String str,String mou,String m) throws Exception{
     //模hex
     String modulus =mou;
     //私钥指数hex
     String private_exponent = m;

     RSAPrivateKey priKey = getPrivateKey(modulus, private_exponent);

     return decryptByPrivateKey(HexUtil.hexStringToBytes(str), priKey);
 }
 //获取模块信息
 public static Map<String,String> getModulus () throws NoSuchAlgorithmException{
     KeyPair keyPair = genRSAKeyPair();
     Map<String,String> map = new HashMap<String,String>();
     //生成公钥和私钥
     RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
     RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
     //模hex
     String modulus = publicKey.getModulus().toString(16);
     //公钥指数hex
     String public_exponent = publicKey.getPublicExponent().toString(16);
     //私钥指数hex
     String private_exponent = privateKey.getPrivateExponent().toString(16);
     map.put("g", public_exponent);
     map.put("m", private_exponent);
     map.put("modu", modulus);
    return map;
 }
    public static void main(String[] args) throws Exception {
        KeyPair keyPair = genRSAKeyPair();

        //生成公钥和私钥
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();


        //模hex
        String modulus = publicKey.getModulus().toString(16);
        //String modulus="9633b6409d39b004002716bffb1b219d00ce4d8d772fe740a3942de624a7f53ebcd3ff41cb5c2a44900c5194812b2f2d479d6925a195d3cf0f32e2a2f0be735d39d3c4c80bb758e5780dbdd372ec54ef2100963ff1b7ec2ac952bd85d11d729c9decc9c2c48668c107a384eb8e456aabe0a3a6eaa0a62a63864d1759dc20486d";
        //公钥指数hex
        String public_exponent = publicKey.getPublicExponent().toString(16);
        //String public_exponent = "10001";
        //私钥指数hex
        String private_exponent = privateKey.getPrivateExponent().toString(16);
        //String private_exponent = "6c708b2d1d15eff9036f35228794eff09d0b54bc4487662aa9aeaa7094985a1be05221e08b844fd3ce37c69233ab4cd520f6095aaccd31ed34a8e52d04284bbaafc178d607432e2728778e5f0697d7affe0375dd68d9dfcbab7e8f7b829247c1adcc5773cab6223088f9136bcc86e1160dee8939994684a8606e6cf7fa4d6495";

        System.out.println("public_modulus: " + modulus);
        System.out.println("public_exponent: " + public_exponent);
        System.out.println("private_exponent: " + private_exponent);

        //明文
        String plaintStr = "我的一家在我的一家我的一家";
        System.out.println("plaintStr: " + plaintStr);

        //使用模和指数生成公钥和私钥
        RSAPublicKey pubKey = getPublicKey(modulus, public_exponent);
        RSAPrivateKey priKey = getPrivateKey(modulus, private_exponent);
        //公钥加密后的密文
        byte[] encryptStr = encryptByPublicKey(plaintStr.getBytes("utf-8"), pubKey);
        System.out.println("encryptStr: " + HexUtil.bytesToHexString(encryptStr));
        String jmh = HexUtil.bytesToHexString(encryptStr);
        System.out.println("start");
        //私钥解密后的明文
        System.out.println("decryptStr: " + decryptByPrivateKey(HexUtil.hexStringToBytes(jmh), priKey));
    }

} 

