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
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.bouncycastle.tsp.TimeStampToken;

import ru.CryptoPro.CAdES.CAdESSignature;
import ru.CryptoPro.CAdES.CAdESSigner;
import ru.CryptoPro.CAdES.CAdESType;
import ru.CryptoPro.JCP.JCP;

/**
 * Различные константы для примеров.
 * 
 * @author Yevgeniy, 17/04/2012
 *
 */
public class Configuration {

	/**
	 * Алиас ключа.
	 */
	private static final String KEY_ALIAS = "ikarpov_t1"; //cryptopro
//	private static final String KEY_ALIAS = "cs_osmp_ocsp_test"; //infotecs_2011
//	private static final String KEY_ALIAS = "Test-2012"; //infotecs_2012
	/**
	 * Пароль к ключу.
	 */
	private static final char[] KEY_PASSWORD = "qwerty".toCharArray();
	/**
	 * Данные для подписи.
	 */
	public static final byte[] DATA = "Security is only our business.".getBytes();
	/**
	 * Место хранения файлов.
	 */
	public static final String TEST_DIR = "/home/pls/Work/test-projects/cryptocades/tmp/";
	/**
	 * Имя файла с подписью для сохранения.
	 */
	public static final String SIGNATURE_FILENAME = "CadesSignature.sig";
	/**
	 * Отступ при печати.
	 */
	private static final String TAG = "***";
	/**
	 * Имя файла с CRL для проверки подписи CAdES-BES. Можно быть null.
	 */
	public static final String CRL_FILENAME = null;
	/**
	 * Адрес службы штампов.
	 */
//	public static final String TSA_ADDRESS = "http://193.232.60.72:8777/tsp"; //infotecs
	public static final String TSA_ADDRESS = "http://www.cryptopro.ru/tsp/tsp.srf"; //cryptopro
	
	/**
	 * Загрузка закрытого ключа и цепочки сертификатов из пользовательского
	 * контейнера.
     *
	 * @param chain Цепочка сертификатов. Заполнится после загрузки хранилища.
	 * @return закрытый ключ из контейнера.
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws IOException
	 * @throws UnrecoverableKeyException
	 */
	public static PrivateKey loadConfiguration(Collection<X509Certificate> chain) 
		throws KeyStoreException, NoSuchAlgorithmException, CertificateException, 
		IOException, UnrecoverableKeyException {
		
		return loadConfiguration(JCP.HD_STORE_NAME, null, null, Configuration.KEY_ALIAS, 
			Configuration.KEY_PASSWORD, chain);
	}
	
	/**
	 * Загрузка закрытого ключа и цепочки сертификатов из пользовательского
	 * контейнера.
     *
     * @param storeType Тип хранилища.
     * @param storeFile Путь к хранилищу.
     * @param storePassword Пароль хранилища.
     * @param alias Идентификатор ключа.
     * @param password Пароль ключа.
	 * @param chain Цепочка сертификатов. Заполнится после загрузки хранилища.
	 * @return закрытый ключ из контейнера.
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws IOException
	 * @throws UnrecoverableKeyException
	 */
	public static PrivateKey loadConfiguration(String storeType, String storeFile,
		char[] storePassword, String alias, char[] password, Collection<X509Certificate> 
		chain) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, 
		IOException, UnrecoverableKeyException {
		
		KeyStore keyStore = KeyStore.getInstance(storeType);
		keyStore.load(storeFile == null ? null : new FileInputStream(storeFile), 
			storePassword);
		
		PrivateKey privateKey = 
			(PrivateKey) keyStore.getKey(alias, password);

		// Получаем цепочку сертификатов. 
		List<Certificate> lChain = 
			Arrays.asList(keyStore.getCertificateChain(alias));
	
		// Конвертируем цепочку в X509Certificate.
		Collection<X509Certificate> xChain = 
			Arrays.asList((lChain).toArray(new X509Certificate[lChain.size()]));
		
		chain.addAll(xChain);
		
		return privateKey;
	}
	
	/**
	 * Вывод информации об отдельном подписанте.
	 * 
	 * @param signer Подписант.
	 * @param index Индекс подписи.
	 * @param tab Отступ для удобства печати.
	 */
	private static void printSignerInfo(CAdESSigner signer, int index, String tab) {
		
		X509Certificate signerCert = signer.getSignerCertificate();
		
		System.out.println(tab + " Signature #" + index + " (" + 
			CAdESType.getSignatureTypeName(signer.getSignatureType()) + ")" + 
			(signerCert != null ? (" verified by " + signerCert.getSubjectDN()) : "" ));
						
		if ( signer.getSignatureType() == CAdESType.CAdES_X_Long_Type_1 ) {
							
			TimeStampToken signatureTimeStamp = signer.getSignatureTimestampToken();
			TimeStampToken cadesCTimeStamp = signer.getCAdESCTimestampToken();
			
			if (signatureTimeStamp != null) {
				System.out.println(tab + TAG + " Signature timestamp set: " + 
					signatureTimeStamp.getTimeStampInfo().getGenTime());
			}
			
			if (cadesCTimeStamp != null) {
				System.out.println(tab + TAG + " CAdES-C timestamp set: " + 
					cadesCTimeStamp.getTimeStampInfo().getGenTime());
			}
		}
		
		printCountersignerInfos(signer.getCAdESCountersignerInfos());
	}
	
	/**
	 * Вывод информации о заверителях отдельного подписанта.
	 * 
	 * @param countersigners Список заверителей.
	 */
	private static void printCountersignerInfos(CAdESSigner[] countersigners) {
		
		// Заверяющие подписи.
		int countersignerIndex = 1;
		for (CAdESSigner countersigner : countersigners) {
			printSignerInfo(countersigner, countersignerIndex++, TAG);
		}
	}
	
	/**
	 * Вывод информации о подписи: кто подписал, тип подписи, штампы времени.
	 * 
	 * @param signature Подпись CAdES.
	 */
	public static void printSignatureInfo(CAdESSignature signature) {
		
		// Список подписей.
		int signerIndex = 1;
		for (CAdESSigner signer : signature.getCAdESSignerInfos()) {
			printSignerInfo(signer, signerIndex++, "");
		}
	}
}
