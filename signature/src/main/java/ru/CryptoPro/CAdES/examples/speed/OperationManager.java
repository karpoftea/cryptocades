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
package ru.CryptoPro.CAdES.examples.speed;

import java.io.FileInputStream;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
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
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.ocsp.OCSPException;

import ru.CryptoPro.CAdES.CAdESSignature;
import ru.CryptoPro.CAdES.CAdESSigner;
import ru.CryptoPro.CAdES.CAdESType;
import ru.CryptoPro.CAdES.examples.Configuration;
import ru.CryptoPro.CAdES.exception.CAdESException;
import ru.CryptoPro.JCP.JCP;

/**
 * Класс для проверки производительности определенной операции  - создание, 
 * проверка или усовершенствование подписи CAdES. Все настройки - ключ, 
 * сертификаты, СОС - загружаются по параметрам, записанным в файле Configuration.
 * 
 * @author Yevgeniy, 26/04/2012
 *
 */
public class OperationManager {

	/**
	 * Тип операции, выполняемой в потоке.
	 */
	public static enum OperationType { otSignCadesBes, otSignCadesXLongType1,
		otEnhanceCadesBes, otVerifyCadesBes, otVerifyCadesXLongType1};
	/**
	 * Тип выполняемой операции.
	 */
	private OperationType operationType;
	/**
	 * Цепочка сертификатов. Используется для создания, усовершенствования или
	 * проверки подписи.
	 */
	private Collection<X509Certificate> chain = new ArrayList<X509Certificate>();
	/**
	 * СОС. Используется для проверки подписи.
	 */
	private Collection<X509CRL> crls = null;
	/**
	 * Закрытый ключ. Используется для подписи.
	 */
	private PrivateKey privateKey = null;
		
	/**
	 * Конструктор. Загрузка цепочки сертификатов и закрытого ключа из 
	 * Configuration.
	 * 
	 * @param otype Тип операции.
	 */
	public OperationManager(OperationType otype) {
		
		operationType = otype;
		
		try {
			
			// Если задан CRL, то читаем его из файла.
			if (Configuration.CRL_FILENAME != null) {
							
				X509CRL crl = (X509CRL) CertificateFactory.getInstance("X.509")
					.generateCRL(new FileInputStream(Configuration.CRL_FILENAME));
				
				crls = Collections.singletonList(crl);
			}
			
			// Закрытый ключ для подписи и сертификаты.
			privateKey = Configuration.loadConfiguration(chain);
		
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * Выполнение операции в зависимости от типа.
	 * 
	 * @param data Подпись CAdES для проверки.
	 * @return подпись CAdES.
	 */
	public byte[] execute(byte[] data) {
		
		try {
		
			switch (operationType) {
			
				case otSignCadesBes:
				case otSignCadesXLongType1:	{
					return sign();
				}
				
				case otVerifyCadesBes:
				case otVerifyCadesXLongType1: {
					verify(data);
					break;
				}
				
				case otEnhanceCadesBes: {
					return enhance(data);
				}
			}
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		
		return null;
	}
	
	/**
	 * Формирование совмещенной подписи в зависимости от типа.
	 * 
	 * @return подпись CAdES.
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws CMSException
	 * @throws CAdESException
	 * @throws InvalidKeyException
	 * @throws CertificateException
	 * @throws CRLException
	 * @throws IOException
	 */
	private byte[] sign() throws NoSuchAlgorithmException, NoSuchProviderException, 
		CMSException, CAdESException, InvalidKeyException, CertificateException, 
		CRLException, IOException {
		
		CAdESSignature cadesSignature = new CAdESSignature(false);
		
		switch (operationType) {
		
			case otSignCadesBes: {
				cadesSignature.addSigner(privateKey, chain, CAdESType.CAdES_BES, null);
				break;
			}
			
			case otSignCadesXLongType1: {
				cadesSignature.addSigner(privateKey, chain, CAdESType.CAdES_X_Long_Type_1, 
					Configuration.TSA_ADDRESS);
				break;
			}
		}
		
		return cadesSignature.sign(Configuration.DATA);
	}
	
	/**
	 * Проверка совмещенной подписи.
	 * 
	 * @param data Подпись для проверки.
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws CertStoreException
	 * @throws CMSException
	 * @throws CAdESException
	 * @throws CRLException
	 * @throws CertificateException
	 * @throws IOException
	 * @throws OCSPException
	 * @throws ParseException
	 */
	private void verify(byte[] data) throws NoSuchAlgorithmException, NoSuchProviderException, 
		CertStoreException, CMSException, CAdESException, CRLException, CertificateException, 
		IOException, OCSPException, ParseException {
		
		if (data == null) {
			throw new IllegalArgumentException("Data is null.");
		}
		
		CAdESSignature cadesSignature = new CAdESSignature(data, null, null);
		cadesSignature.verify(chain, crls);
	}
	
	/**
	 * Усовершенствование подписи CAdES-BES до CAdES-X Long Type 1.
	 * 
	 * @param data Подпись CAdES-BES.
	 * @return усовершенствованная подпись CAdES-X Long Type 1.
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws CertStoreException
	 * @throws CMSException
	 * @throws CAdESException
	 * @throws CertificateException
	 * @throws CRLException
	 * @throws IOException
	 */
	private byte[] enhance(byte[] data) throws NoSuchAlgorithmException, NoSuchProviderException, 
		CertStoreException, CMSException, CAdESException, CertificateException, CRLException, 
		IOException {
		
		if (data == null) {
			throw new IllegalArgumentException("Data is null.");
		}
		
		CAdESSignature cadesSignature = new CAdESSignature(data, null, null);
		
		// Список всех подписантов в исходной подписи.
		Collection<SignerInformation> srcSignerInfos = new ArrayList<SignerInformation>();
								
		for (CAdESSigner signer : cadesSignature.getCAdESSignerInfos()) {
			srcSignerInfos.add(signer.getSignerInfo());
		}
		
		// Получаем только первого подписанта CAdES-BES, его усовершенствуем. Остальных не 
		// трогаем.
		CMSSignedData srcSignedData = cadesSignature.getSignedData();
		CAdESSigner srcSigner = cadesSignature.getCAdESSignerInfo(0);
					
		// Исключаем его из исходного списка, т.к. его место займет усовершенствованный 
		// подписант.
		srcSignerInfos.remove(srcSigner.getSignerInfo());
					
		// Улучшаем CAdES-BES до CAdES-X Long Type 1.
		srcSigner.enhance(JCP.PROVIDER_NAME, JCP.GOST_DIGEST_OID, chain, 
			Configuration.TSA_ADDRESS, CAdESType.CAdES_X_Long_Type_1);
								
		// Усовершенствованный подписант.
		SignerInformation enhSigner = srcSigner.getSignerInfo();
					
		// Добавляем его в исходный список подписантов.
		srcSignerInfos.add(enhSigner);
		
		// Список подписантов.
		SignerInformationStore dstSignerInfoStore = 
			new SignerInformationStore(srcSignerInfos);
					
		// Обновляем исходную подпись c ее начальным списком подписантов на тот же,
		// но с первым усовершенствованным подписантом.
		CMSSignedData dstSignedData = 
			CMSSignedData.replaceSigners(srcSignedData, dstSignerInfoStore);
		
		return dstSignedData.getEncoded();
	}
}
