package my.sign;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.ocsp.OCSPException;
import ru.CryptoPro.CAdES.CAdESSignature;
import ru.CryptoPro.CAdES.CAdESSigner;
import ru.CryptoPro.CAdES.CAdESType;
import ru.CryptoPro.CAdES.exception.CAdESException;

import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CRLException;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class DualSignerBugReport {

	public static void main(String[] args)
			throws CAdESException, CRLException, IOException, InvalidKeyException, NoSuchProviderException, CMSException, NoSuchAlgorithmException, KeyStoreException,
				   CertificateException, UnrecoverableKeyException, OCSPException, CertStoreException, ParseException, SignatureException {

		byte[] sign = createSignature();

		System.out.println("First signing results:");
		CAdESSignature signature = verify(sign);
		printSigners(signature, System.out);

		sign = addSigner(sign);

		System.out.println("Second signing results:");
		signature = verify(sign);
		printSigners(signature, System.out);
	}

	private static byte[] addSigner(byte[] sign)
			throws CAdESException, NoSuchProviderException, CMSException, NoSuchAlgorithmException, IOException, KeyStoreException, CertificateException,
			UnrecoverableKeyException, CRLException, InvalidKeyException {

		CAdESSignature signature = new CAdESSignature(sign, null, null);
		List<SignerInformation> oldSigners = new ArrayList<SignerInformation>();
		for (CAdESSigner signer : signature.getCAdESSignerInfos()) {
			oldSigners.add(signer.getSignerInfo());
		}

		Credentials credentials = getCredentials(TEST2012_KEY_ALIAS, TEST2012_KEY_PASS);

		signature = new CAdESSignature(false);
		signature.addSigner(credentials.key, credentials.chain, CAdESType.CAdES_X_Long_Type_1, INFOTECS_TSA_URL);
		sign = signature.sign(DATA);

		signature = new CAdESSignature(sign, null, null);
		List<SignerInformation> allSigners = new ArrayList<SignerInformation>();
		for (CAdESSigner signer : signature.getCAdESSignerInfos()) {
			allSigners.add(signer.getSignerInfo());
		}
		allSigners.addAll(oldSigners);

		return CMSSignedData.replaceSigners(signature.getSignedData(), new SignerInformationStore(allSigners)).getEncoded();
	}

	private static CAdESSignature verify(byte[] sign)
			throws OCSPException, CAdESException, CertStoreException, IOException, CRLException,
				   NoSuchProviderException, ParseException, CertificateException, CMSException, NoSuchAlgorithmException {

		CAdESSignature signature = new CAdESSignature(sign, DATA, CAdESType.CAdES_X_Long_Type_1);
		signature.verify(null);
		return signature;
	}

	private static byte[] createSignature()
			throws CAdESException, CMSException, NoSuchProviderException, NoSuchAlgorithmException, IOException,
				   KeyStoreException, CertificateException, UnrecoverableKeyException, CRLException, InvalidKeyException {

		CAdESSignature signature = new CAdESSignature(false);
		Credentials credentials = getCredentials(IKARPOV_KEY_ALIAS, IKARPOV_KEY_PASS);
		signature.addSigner(credentials.key, credentials.chain, CAdESType.CAdES_X_Long_Type_1, CRYPTOPRO_TSA_URL);
		return signature.sign(DATA);
	}

	private static Credentials getCredentials(String keyAlias, char[] keyPassword)
			throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException {

		KeyStore keyStore = KeyStore.getInstance("HDImageStore");
		try {
			keyStore.load(null, null);

			PrivateKey key = (PrivateKey) keyStore.getKey(keyAlias, keyPassword);

			List<Certificate> lChain =
					Arrays.asList(keyStore.getCertificateChain(keyAlias));
			List<X509Certificate> chain =
					Arrays.asList((lChain).toArray(new X509Certificate[lChain.size()]));

			return new Credentials(key, chain);
		} finally {
			keyStore.store(null, null);
		}
	}

	public static void printSigners(CAdESSignature signature, OutputStream os) throws SignatureException {
		StringBuilder sb = new StringBuilder("Signers:\n");
		CAdESSigner[] cAdESSignerInfos = signature.getCAdESSignerInfos();
		for (CAdESSigner signer : cAdESSignerInfos) {
			sb.append(" sn:").append(signer.getSignerCertificate().getSerialNumber())
					.append(" subject:").append(signer.getSignerCertificate().getSubjectDN().getName())
					.append(" \n");
		}

		try {
			os.write(sb.toString().getBytes());
		} catch (IOException e) {
			throw new SignatureException(e);
		}
	}


	private static class Credentials {

		PrivateKey key;
		List<X509Certificate> chain;

		private Credentials(PrivateKey key, List<X509Certificate> chain) {
			this.key = key;
			this.chain = chain;
		}
	}


	public static final byte[] DATA = "Secret data".getBytes();

	public static final String IKARPOV_KEY_ALIAS = "ikarpov_t1";
	public static final char[] IKARPOV_KEY_PASS = "qwerty".toCharArray();

	public static final String TEST2012_KEY_ALIAS = "Test-2012";
	public static final char[] TEST2012_KEY_PASS = "qwerty".toCharArray();

	public static final String CRYPTOPRO_TSA_URL = "http://www.cryptopro.ru/tsp/tsp.srf";
	public static final String INFOTECS_TSA_URL = "http://193.232.60.72:8777/tsp";
}
