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
import ru.CryptoPro.JCP.tools.Array;

/**
 * Пример заверения подписи CAdES-BES двумя подписями CAdES-X Long Type 1.
 * 
 * @author Yevgeniy, 17/04/2012
 *
 */
public class CountersignatureExample {

	/**
	 * @param args
	 */
	public static void main(String[] args) throws InvalidAlgorithmParameterException {

		try {
		
			Collection<X509Certificate> chain = new ArrayList<X509Certificate>();
			PrivateKey privateKey = Configuration.loadConfiguration(chain);

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
			
			// 2. Заверение подписи.
		
			// Получаем только первого подписанта, которого заверим. Остальных не трогаем.
			CAdESSigner srcSigner = cadesSignature.getCAdESSignerInfo(0);
			
			// Исключаем его из исходного списка, т.к. его место займет подписант с заверителями.
			srcSignerInfos.remove(srcSigner.getSignerInfo());
					
			// Создаем заверяющую подпись.
			CAdESSignature counterSignature = new CAdESSignature();
					
			// Добавляем заверяющего подписанта. Последний параметр true, что определяет
			// тип подписанта (заверяющий).
			counterSignature.addSigner(privateKey, chain, CAdESType.CAdES_X_Long_Type_1, 
				Configuration.TSA_ADDRESS, true);
					
			// Подписываем на данных заверяемой подписи.
			counterSignature.sign(srcSigner.getSignerInfo().getSignature());
					
			// Получаем единственного заверителя.
			CAdESSigner counterSigner = counterSignature.getCAdESSignerInfo(0);

			// Добавляем их к исходной подписи.
			srcSigner.addCountersigner(counterSigner.getSignerInfo());
			srcSigner.addCountersigner(counterSigner.getSignerInfo());
					
			// Получаем заверенного подписанта.
			SignerInformation newSigner = srcSigner.getSignerInfo();
			
			// Добавляем его в исходный список подписантов.
			srcSignerInfos.add(newSigner);

			CMSSignedData srcCMSSignedData = cadesSignature.getSignedData();
					
			// Обновляем исходную подпись c ее начальным списком подписантов на тот же,
			// но с первым заверенным подписантом.
			CMSSignedData dstCMSSignedData = CMSSignedData.replaceSigners(srcCMSSignedData, 
				new SignerInformationStore(srcSignerInfos));

			Array.writeFile(Configuration.TEST_DIR + "countersignature_" + Configuration.SIGNATURE_FILENAME, 
				dstCMSSignedData.getEncoded());

			// 3. Проверка заверенной и заверяющих подписей.
		
			// Проверяем подпись.
			cadesSignature = new CAdESSignature(dstCMSSignedData.getEncoded(), null, null);
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
