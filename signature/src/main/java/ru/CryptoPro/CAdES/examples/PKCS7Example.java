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
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CRLException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.ocsp.OCSPException;

import ru.CryptoPro.CAdES.CAdESSignature;
import ru.CryptoPro.CAdES.exception.CAdESException;
import ru.CryptoPro.JCP.JCP;
import ru.CryptoPro.JCP.tools.Array;

/**
 * Пример формирования простой подписи PKCS7 с помощью BouncyCastle и проверки
 * CAdES API.
 * 
 * @author Yevgeniy, 20/04/2012
 *
 */
public class PKCS7Example {

	/**
	 * @param args
	 */
	public static void main(String[] args) {

		// Этот вызов делается автоматически при использовании класса CAdESSignature,
		// однако тут необходимо его выполнить специально, т.к. начинаем работать с ГОСТ
		// без упоминания CAdESSignature.
		ru.CryptoPro.CAdES.tools.Utility.initJCPAlgorithms();
		
		try {
		
			Collection<X509Certificate> chain = new ArrayList<X509Certificate>();
			PrivateKey privateKey = Configuration.loadConfiguration(chain);
			
			// Сертификат подписи - первый в списке.
			X509Certificate signerCert = chain.iterator().next();
			CertStore certStore = CertStore.getInstance("Collection", 
				new CollectionCertStoreParameters(chain), "BC");
			
			// Подготавливаем подпись.
			CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
			generator.addSigner(privateKey, signerCert, JCP.GOST_EL_DH_OID, JCP.GOST_DIGEST_OID);
			generator.addCertificatesAndCRLs(certStore);
			  
			// Создаем совмещенную подпись PKCS7.
			CMSProcessable content = new CMSProcessableByteArray(Configuration.DATA);
			CMSSignedData signedData = generator.generate(content, true, JCP.PROVIDER_NAME);
			 
			// Сформированная подпись.
			byte[] pkcs7 = signedData.getEncoded();
			
			Array.writeFile(Configuration.TEST_DIR + "pkcs7.bin", pkcs7);
			
			// Подпись в тесте была совмещенная, потому данные равны null. Предположим, что
			// подписей несколько, тогда лучше указать тип null и положиться на самоопределение
			// типа подписи.
			CAdESSignature pkcs7Signature = new CAdESSignature(pkcs7, null, null);
			
			// Если задан CRL, то читаем его из файла.
			if (Configuration.CRL_FILENAME != null) {
							
				X509CRL crl = (X509CRL) CertificateFactory.getInstance("X.509")
					.generateCRL(new FileInputStream(Configuration.CRL_FILENAME));
							
				pkcs7Signature.verify(chain, Collections.singletonList(crl));
							
			} else {
				pkcs7Signature.verify(chain);
			}
			
			Configuration.printSignatureInfo(pkcs7Signature);
			
		} catch (IOException e) {
			e.printStackTrace();
		} catch (UnrecoverableKeyException e) {
			e.printStackTrace();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		} catch (CertStoreException e) {
			e.printStackTrace();
		} catch (CMSException e) {
			e.printStackTrace();
		} catch (CAdESException e) {
			System.out.println(e.getMessage() + " (" + e.getErrorCode() + ")");
		} catch (CRLException e) {
			e.printStackTrace();
		}
	}

}
