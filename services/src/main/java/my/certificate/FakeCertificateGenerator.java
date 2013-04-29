package my.certificate;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

public class FakeCertificateGenerator {

	public static Pair<PrivateKey, X509Certificate> generateCertificate()
			throws IOException, NoSuchProviderException, OperatorCreationException, CertificateException {
		Security.addProvider(new BouncyCastleProvider());

		KeyPair keyPair = generateKeyPair();
		X509Certificate certificate = generateX509Certificate(keyPair);
		return new Pair<PrivateKey, X509Certificate>(keyPair.getPrivate(), certificate);
	}

	static KeyPair generateKeyPair() {
		try {
			KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
			kpGen.initialize(1024, new SecureRandom());
			return kpGen.generateKeyPair();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	static X509Certificate generateX509Certificate(KeyPair keyPair) {
		try {
			X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(
					new X500Name("CN=Qiwi Fake CA"),
					new BigInteger(String.valueOf(System.currentTimeMillis())),
					new Date(System.currentTimeMillis() - 10000),
					new Date(System.currentTimeMillis() + 10000),
					new X500Name("CN=Qiwi User"),
					SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded())
			);

			AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder()
					.find("SHA1withRSA");
			AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder()
					.find(sigAlgId);
			AsymmetricKeyParameter keyParameter = PrivateKeyFactory.createKey(keyPair.getPrivate().getEncoded());

			ContentSigner signer = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(keyParameter);

			X509CertificateHolder holder = certificateBuilder.build(signer);
			X509CertificateStructure asn1X509CertStructure = holder.toASN1Structure();

			return toX509Certificate(asn1X509CertStructure.getEncoded());
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public static X509Certificate toX509Certificate(byte[] from) {
		try {
			CertificateFactory cf = CertificateFactory.getInstance("X509");
			return  (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(from));
		} catch (CertificateException e) {
			throw new IllegalStateException(e);
		}
	}
}