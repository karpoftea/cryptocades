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

import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CRLException;
import java.security.cert.CertStoreException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.ocsp.OCSPException;

import ru.CryptoPro.CAdES.CAdESSignature;
import ru.CryptoPro.CAdES.CAdESType;
import ru.CryptoPro.CAdES.exception.CAdESException;
import ru.CryptoPro.JCP.tools.Array;

/**
 * Пример формирования и проверки подписи CAdES на алгоритмах SHA-1 и RSA.
 * 
 * @author Yevgeniy, 04/05/2012
 *
 */
public class RSASignatureExample {

	/**
	 * Путь к контейнеру с сертификатами и ключом.
	 */
	private static final String RSA_STORE = "C:\\merlin\\keys\\RSA_test2.pfx";
	/**
	 * Пароль к контейнеру.
	 */
	private static final char[] RSA_STORE_PASSWORD = "123456".toCharArray();
	/**
	 * Идентификатор ключа.
	 */
	private static final String RSA_KEY_ALIAS = "RSA_test2";
	/**
	 * Пароль к ключу.
	 */
	private static final char[] RSA_KEY_PASSWORD = "123456".toCharArray();
	/**
	 * Идентификатор алгоритма хэширования.
	 */
	private static final String OID_SHA1 = "1.3.14.3.2.26";
	/**
	 * Идентификатор алгоритма подписи.
	 */
	private static final String OID_RSA = "1.3.14.3.2.29";
	
	/**
	 * @param args
	 */
	public static void main(String[] args) {
		
		try {
			
			Collection<X509Certificate> chain = new ArrayList<X509Certificate>();
			PrivateKey privateKey = Configuration.loadConfiguration("PKCS12", RSA_STORE,
				RSA_STORE_PASSWORD, RSA_KEY_ALIAS, RSA_KEY_PASSWORD, chain);
				
			CAdESSignature cadesSignature = new CAdESSignature(false);
		
			// Создаем подписанта CAdES-BES.
			cadesSignature.addSigner(BouncyCastleProvider.PROVIDER_NAME, OID_SHA1, 
				OID_RSA, privateKey, chain, CAdESType.CAdES_BES, null, false);
			// Создаем подписанта CAdES-X Long Type 1.
			cadesSignature.addSigner(BouncyCastleProvider.PROVIDER_NAME, OID_SHA1, OID_RSA, 
				privateKey, chain, CAdESType.CAdES_X_Long_Type_1, Configuration.TSA_ADDRESS, false);
		
			// Завершаем создание подписи с двумя подписантами.
			byte[] cadesCms = cadesSignature.sign(Configuration.DATA);
		
			Array.writeFile(Configuration.TEST_DIR + "rsa_" + Configuration.SIGNATURE_FILENAME, cadesCms);
		
			// Проверяем подпись.
			cadesSignature = new CAdESSignature(cadesCms, null, null);
			
			// Если задан CRL, то читаем его из файла.
			if (Configuration.CRL_FILENAME != null) {
										
				X509CRL crl = (X509CRL) CertificateFactory.getInstance("X.509")
					.generateCRL(new FileInputStream(Configuration.CRL_FILENAME));
										
				cadesSignature.verify(chain, Collections.singletonList(crl));
										
			} else {
				cadesSignature.verify(chain);
			}
			
			Configuration.printSignatureInfo(cadesSignature);
		}
		catch (IOException e) {
			e.printStackTrace();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (UnrecoverableKeyException e) {
			e.printStackTrace();
		} catch (CRLException e) {
			e.printStackTrace();
		} catch (CAdESException e) {
			e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
		}

	}

}
