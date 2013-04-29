/**
 * Copyright 2004-2012 Crypto-Pro. All rights reserved.
 * Этот файл содержит информацию, являющуюся
 * собственностью компании Крипто-Про.
 *
 * Любая часть этого файла не может быть скопирована,
 * исправлена, переведена на другие языки,
 * локализована или модифицирована любым способом,
 * откомпилирована, передана по сети с или на
 * любую компьютерную систему без предварительного
 * заключения соглашения с компанией Крипто-Про.
 */
package ru.CryptoPro.CAdES.examples;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;

import org.bouncycastle.cms.CMSException;

import ru.CryptoPro.CAdES.CAdESSignature;
import ru.CryptoPro.CAdES.CAdESType;
import ru.CryptoPro.CAdES.exception.CAdESException;
import ru.CryptoPro.JCP.tools.Array;

/**
 * Пример создания подписи CAdES-BES.
 * 
 * @author Yevgeniy, 17/04/2012
 *
 */
public class SignExample {

	/**
	 * @param args
	 */
	public static void main(String[] args) {

		try {
			Collection<X509Certificate> chain = new ArrayList<X509Certificate>();
			PrivateKey privateKey = Configuration.loadConfiguration(chain);
				
			CAdESSignature cadesSignature = new CAdESSignature(false);
		
			// Создаем подписанта CAdES-BES.
			cadesSignature.addSigner(privateKey, chain, CAdESType.CAdES_BES, null);
			// Создаем подписанта CAdES-X Long Type 1.
			cadesSignature.addSigner(privateKey, chain, CAdESType.CAdES_X_Long_Type_1, 
				Configuration.TSA_ADDRESS);
		
			// Завершаем создание подписи с двумя подписантами.
			byte[] cadesCms = cadesSignature.sign(Configuration.DATA);
		
			Array.writeFile(Configuration.TEST_DIR + Configuration.SIGNATURE_FILENAME, cadesCms);
		
		} catch (IOException e) {
			e.printStackTrace();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (UnrecoverableKeyException e) {
			e.printStackTrace();
		} catch (CAdESException e) {
			e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
		}
	}
}
