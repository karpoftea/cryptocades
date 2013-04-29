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
import java.util.List;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.ocsp.OCSPException;

import ru.CryptoPro.CAdES.CAdESSignature;
import ru.CryptoPro.CAdES.CAdESSigner;
import ru.CryptoPro.CAdES.CAdESType;
import ru.CryptoPro.CAdES.exception.CAdESException;
import ru.CryptoPro.JCP.JCP;
import ru.CryptoPro.JCP.tools.Array;

/**
 * Пример усовершенствования подписи CAdES-BES до CAdES-X Long Type 1.
 * 
 * @author Yevgeniy, 17/04/2012
 *
 */
public class EnhanceExample {

	/**
	 * @param args
	 */
	public static void main(String[] args) {

		try {
			
			Collection<X509Certificate> chain = new ArrayList<X509Certificate>();
			Configuration.loadConfiguration(chain);

			// 1. Загрузка и "проверка" подписи. 
		
			// Читаем подпись из файла.
			byte[] cadesCms = Array.readFile(Configuration.TEST_DIR + Configuration.SIGNATURE_FILENAME);
				
			// Подпись в тесте была совмещенная, потому данные равны null. Предположим, что
			// подписей несколько, тогда лучше указать тип null и положиться на самоопределение
			// типа подписи.
			CAdESSignature cadesSignature = new CAdESSignature(cadesCms, null, null);

			// Список CRL.
			List<X509CRL> crlList = null;
			
			// Если задан CRL, то читаем его из файла.
			if (Configuration.CRL_FILENAME != null) {
							
				X509CRL crl = (X509CRL) CertificateFactory.getInstance("X.509")
					.generateCRL(new FileInputStream(Configuration.CRL_FILENAME));
					
				crlList = Collections.singletonList(crl);
				cadesSignature.verify(chain, crlList);
							
			} else {
				cadesSignature.verify(chain);
			}
			
			// Список всех подписантов в исходной подписи.
			Collection<SignerInformation> srcSignerInfos = new ArrayList<SignerInformation>();
						
			for (CAdESSigner signer : cadesSignature.getCAdESSignerInfos()) {
				srcSignerInfos.add(signer.getSignerInfo());
			}
			
			// 2. Усовершенствование подписи.
		
			// Получаем только первого подписанта CAdES-BES, его усовершенствуем. Остальных не трогаем.
			CMSSignedData srcSignedData = cadesSignature.getSignedData();
			CAdESSigner srcSigner = cadesSignature.getCAdESSignerInfo(0);
			
			// Исключаем его из исходного списка, т.к. его место займет усовершенствованный подписант.
			srcSignerInfos.remove(srcSigner.getSignerInfo());
			
			// Улучшаем CAdES-BES до CAdES-X Long Type 1.
			srcSigner.enhance(JCP.PROVIDER_NAME, JCP.GOST_DIGEST_OID, chain, 
				Configuration.TSA_ADDRESS, CAdESType.CAdES_X_Long_Type_1);
						
			// Усовершенствованный подписант.
			SignerInformation enhSigner = srcSigner.getSignerInfo();
			
			// Добавляем его в исходный список подписантов.
			srcSignerInfos.add(enhSigner);
			
			// Список подписантов.
			SignerInformationStore dstSignerInfoStore = new SignerInformationStore(srcSignerInfos);
			
			// Обновляем исходную подпись c ее начальным списком подписантов на тот же,
			// но с первым усовершенствованным подписантом.
			CMSSignedData dstSignedData = 
				CMSSignedData.replaceSigners(srcSignedData, dstSignerInfoStore);
			
			Array.writeFile(Configuration.TEST_DIR + "enhanced_" + Configuration.SIGNATURE_FILENAME, 
				dstSignedData.getEncoded());
		
			// 3. Проверка усовершенствованной подписи.
		
			// Проверяем подпись.
			cadesSignature = new CAdESSignature(dstSignedData.getEncoded(), null, null);
			cadesSignature.verify(chain, crlList);
			
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
		} catch (CAdESException e) {
			e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
		} catch (CRLException e) {
			e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
		}
	}

}
