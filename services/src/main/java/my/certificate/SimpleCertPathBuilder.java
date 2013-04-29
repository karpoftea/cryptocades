package my.certificate;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.logging.Logger;

public class SimpleCertPathBuilder {

	private static final Logger log = Logger.getLogger(SimpleCertPathBuilder.class.getName());

	private final KeyStore keyStore;

	public SimpleCertPathBuilder(KeyStore keyStore) {
		this.keyStore = keyStore;
	}

	public KeyStore getKeyStore() {
		return keyStore;
	}

	public PKIXCertPathBuilderResult buildCertPath(X509Certificate certificate)
			throws CertPathBuilderException, InvalidAlgorithmParameterException,
			NoSuchProviderException, NoSuchAlgorithmException, KeyStoreException {
		log.info(
				"building cert path for certificate sn:" + certificate.getSerialNumber().toString(16) +
				" subject:" + certificate.getSubjectX500Principal()
		);

		PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult) getCertPathBuilder().build(createCertPathBuilderParams(certificate));

		log.info(
				"building cert path for certificate sn:" + certificate.getSerialNumber().toString(16) +
						" subject:" + certificate.getSubjectX500Principal() +
						" OK"
		);
		return result;
	}

	CertPathBuilder getCertPathBuilder() throws NoSuchProviderException, NoSuchAlgorithmException {
		return CertPathBuilder.getInstance(PKIX_ALG, SUN);
	}

	PKIXBuilderParameters createCertPathBuilderParams(X509Certificate certificate)
			throws KeyStoreException, InvalidAlgorithmParameterException {
		X509CertSelector selector = new X509CertSelector();
		selector.setCertificate(certificate);
		PKIXBuilderParameters params = new PKIXBuilderParameters(getKeyStore(), selector);
		params.setRevocationEnabled(false);
		return params;
	}

	private static final String PKIX_ALG = "PKIX";
	private static final String SUN = "SUN";
}