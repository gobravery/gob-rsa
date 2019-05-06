package com.gobravery.rsa.jsbn;

import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
//import org.springframework.context.annotation.Scope;
//import org.springframework.stereotype.Component;
//import org.springframework.web.context.WebApplicationContext;

//@Component("encryptionService")
//@Scope(value = WebApplicationContext.SCOPE_SESSION)
public class EncryptionService {
	private final Logger logger = LoggerFactory.getLogger(this.getClass());
	private static Map<String, String> params;
	public static final String er="-1";
	public EncryptionService() {
		try {
			params = RSAUtil.getModulus();
		} catch (NoSuchAlgorithmException e) {
			params = null;
			// e.printStackTrace();
			logger.warn("创建加密参数失败>>>>", e);
		}
	}

	/**
	 * 加密
	 * 
	 * @param plaintStr
	 * @return
	 */
	public String en(String plaintStr) {
		if (params == null)
			return plaintStr;
		//
		try {
			String modulus = params.get("modu");
			String public_exponent = params.get("g");
			RSAPublicKey pubKey = RSAUtil.getPublicKey(modulus, public_exponent);
			byte[] encryptStr = RSAUtil.encryptByPublicKey(plaintStr.getBytes("utf-8"), pubKey);
			return HexUtil.bytesToHexString(encryptStr);
		} catch (Exception e) {
			logger.warn("加密失败>>>>", e);
			return er;
		}

	}

	/**
	 * 解密
	 * 
	 * @param en
	 * @return
	 */
	public String de(String en) {
		if (params == null)
			return en;
		try {
			String modulus = params.get("modu");
			String private_exponent = params.get("m");
			RSAPrivateKey priKey = RSAUtil.getPrivateKey(modulus, private_exponent);
			return RSAUtil.decryptByPrivateKey(HexUtil.hexStringToBytes(en), priKey);
		} catch (Exception e) {
			logger.warn("解密失败>>>>", e);
			return er;
		}
	}

	/**
	 * 模hex
	 * @return
	 */
	public String getModu() {
		String modulus = params.get("modu");
		return modulus;
	}

	/**
	 * 公钥
	 * @return
	 */
	public String getPublicKey() {
		String g = params.get("g");
		return g;
	}
}
