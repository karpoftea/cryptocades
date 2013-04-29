package my.checker;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

class PBE {

	static byte[] encrypt(char[] passwd, byte[] data) throws Exception {
		PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt, count);
		PBEKeySpec pbeKeySpec = new PBEKeySpec(passwd);
		SecretKeyFactory keyFac = SecretKeyFactory.getInstance(ALG_NAME);
		SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);
		Cipher pbeCipher = Cipher.getInstance(ALG_NAME);
		pbeCipher.init(Cipher.ENCRYPT_MODE, pbeKey, pbeParamSpec);
		return pbeCipher.doFinal(data);
	}

	static byte[] decrypt(char[] passwd, byte[] data) throws Exception {
		PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt, count);
		PBEKeySpec pbeKeySpec = new PBEKeySpec(passwd);
		SecretKeyFactory keyFac = SecretKeyFactory.getInstance(ALG_NAME);
		SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);
		Cipher pbeCipher = Cipher.getInstance(ALG_NAME);
		pbeCipher.init(Cipher.DECRYPT_MODE, pbeKey, pbeParamSpec);
		return pbeCipher.doFinal(data);
	}


	private final static int count = 20;

	private final static byte[] salt = {
			(byte)0xc7, (byte)0x73, (byte)0x21, (byte)0x8c,
			(byte)0x7e, (byte)0xc8, (byte)0xee, (byte)0x99
	};

	private static String ALG_NAME = "PBEWithMD5AndDES";
}