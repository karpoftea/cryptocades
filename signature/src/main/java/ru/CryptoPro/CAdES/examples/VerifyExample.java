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
import org.bouncycastle.ocsp.OCSPException;

import ru.CryptoPro.CAdES.CAdESSignature;
import ru.CryptoPro.CAdES.exception.CAdESException;
import ru.CryptoPro.JCP.tools.Array;

/**
 * Пример проверки подписи CAdES.
 * 
 * @author Yevgeniy, 17/04/2012
 *
 */
public class VerifyExample {

	/**
	 * @param args
	 */
	public static void main(String[] args) {

		try {
		
			Collection<X509Certificate> chain = new ArrayList<X509Certificate>();
			Configuration.loadConfiguration(chain);

			// Читаем подпись из файла.
			byte[] cadesCms = Array.readFile(Configuration.TEST_DIR + Configuration.SIGNATURE_FILENAME);
		
			// Подпись в тесте была совмещенная, потому данные равны null. Предположим, что
			// подписей несколько, тогда лучше указать тип null и положиться на самоопределение
			// типа подписи.
			CAdESSignature cadesSignature = new CAdESSignature(cadesCms, null, null);

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
		}  catch (UnrecoverableKeyException e) {
			e.printStackTrace();
		} catch (CAdESException e) {
			e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
		} catch (CRLException e) {
			e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
		}
	}

}
