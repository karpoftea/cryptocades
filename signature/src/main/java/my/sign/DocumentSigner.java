package my.sign;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import ru.CryptoPro.CAdES.CAdESSignature;
import ru.CryptoPro.CAdES.CAdESSigner;
import ru.CryptoPro.CAdES.CAdESType;
import ru.CryptoPro.CAdES.exception.CAdESException;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class DocumentSigner {

	private final String keyAlias;
	private final char[] keyPassword;
	private final String tsaUrl;
	private final boolean detached;

	public DocumentSigner(String keyAlias, char[] keyPassword, String tsaUrl, boolean detached) {
		this.keyAlias = keyAlias;
		this.keyPassword = keyPassword;
		this.tsaUrl = tsaUrl;
		this.detached = detached;
	}

	public DocumentSigner(String keyAlias, char[] keyPassword, String tsaUrl) {
		this(keyAlias, keyPassword, tsaUrl, false);
	}

	public byte[] sign(byte[] data) throws SignatureException {
		return coSign(null, data);
	}

	public byte[] coSign(byte[] sign, byte[] data) throws SignatureException {
		try {
			Credentials credentials = getCredentials();

			CAdESSignature signature = sign(data, credentials);

			List<SignerInformation> allSigners = getSigners(sign);
			allSigners.addAll(getSigners(signature));

			return CMSSignedData.replaceSigners(signature.getSignedData(), new SignerInformationStore(allSigners)).getEncoded();
		} catch (Exception e) {
			throw new SignatureException(e);
		}
	}

	private CAdESSignature sign(byte[] data, Credentials credentials)
			throws NoSuchAlgorithmException, NoSuchProviderException, CMSException, CAdESException, InvalidKeyException, CertificateException, CRLException, IOException {

		CAdESSignature signature = new CAdESSignature(detached);
		signature.addSigner(credentials.key, credentials.chain, CAdESType.CAdES_X_Long_Type_1, tsaUrl);
		signature.sign(data);
		return signature;
	}

	private List<SignerInformation> getSigners(byte[] sign) throws CAdESException, NoSuchProviderException, CMSException, NoSuchAlgorithmException {
		return sign == null ? new ArrayList<SignerInformation>() : getSigners(new CAdESSignature(sign, null, null));
	}

	private List<SignerInformation> getSigners(CAdESSignature signature) {
		List<SignerInformation> signers = new ArrayList<SignerInformation>();
		for (CAdESSigner signer : signature.getCAdESSignerInfos()) {
			signers.add(signer.getSignerInfo());
		}
		return signers;
	}

	private Credentials getCredentials()
			throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException, NoSuchProviderException {

		KeyStore store = KeyStore.getInstance(STORE_NAME, PROVIDER_NAME);
		try {
			store.load(null, null);

			PrivateKey key = (PrivateKey) store.getKey(keyAlias, keyPassword);

			List<Certificate> certificates = Arrays
					.asList(store.getCertificateChain(keyAlias));
			List<X509Certificate> chain = Arrays
					.asList(certificates.toArray(new X509Certificate[certificates.size()]));

			return new Credentials(key, chain);
		} finally {
			store.store(null, null);
		}
	}


	private class Credentials {

		PrivateKey key;
		List<X509Certificate> chain;

		private Credentials(PrivateKey key, List<X509Certificate> chain) {
			this.key = key;
			this.chain = chain;
		}
	}


	private final static String STORE_NAME = "HDImageStore";
	private final static String PROVIDER_NAME = "JCP";
}