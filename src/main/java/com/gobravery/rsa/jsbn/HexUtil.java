package com.gobravery.rsa.jsbn;

public class HexUtil {

    /**
     * 二进制byte数组转十六进制byte数组
     * byte array to hex
     *
     * @param b byte array
     * @return hex string
     */
    public static String byte2hex(byte[] b) {
        StringBuilder hs = new StringBuilder();
        String stmp;
        for (int i = 0; i < b.length; i++) {
            stmp = Integer.toHexString(b[i] & 0xFF).toUpperCase();
            if (stmp.length() == 1) {
                hs.append("0").append(stmp);
            } else {
                hs.append(stmp);
            }
        }
        return hs.toString();
    }

    /**
     * 十六进制byte数组转二进制byte数组
     * hex to byte array
     *
     * @param hex hex string
     * @return byte array
     */
    public static byte[] hex2byte(String hex)
             throws IllegalArgumentException{
        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException ("invalid hex string");
        }
        char[] arr = hex.toCharArray();
        byte[] b = new byte[hex.length() / 2];
        for (int i = 0, j = 0, l = hex.length(); i < l; i++, j++) {
            String swap = "" + arr[i++] + arr[i];
            int byteint = Integer.parseInt(swap, 16) & 0xFF;
            b[j] = new Integer(byteint).byteValue();
        }
        return b;
    }


     public static String bytesToHexString(byte[] src){
            StringBuilder stringBuilder = new StringBuilder("");
            if (src == null || src.length <= 0) {
                return null;
            }
            for (int i = 0; i < src.length; i++) {
                int v = src[i] & 0xFF;
                String hv = Integer.toHexString(v);
                if (hv.length() < 2) {
                    stringBuilder.append(0);
                }
                stringBuilder.append(hv);
            }
            return stringBuilder.toString();
        }
     private static byte charToByte(char c) {  
            return (byte) "0123456789ABCDEF".indexOf(c);  
        }
     public static byte[] hexStringToBytes(String hexString) {  
            if (hexString == null || hexString.equals("")) {  
                return null;  
            }  
            hexString = hexString.toUpperCase();  
            int length = hexString.length() / 2;  
            char[] hexChars = hexString.toCharArray();  
            byte[] d = new byte[length];  
            for (int i = 0; i < length; i++) {  
                int pos = i * 2;  
                d[i] = (byte) (charToByte(hexChars[pos]) << 4 | charToByte(hexChars[pos + 1]));  
            }  
            return d;  
        }  

}
