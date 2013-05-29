package my.sign;

import my.verify.SignatureVerifier;
import org.testng.Assert;
import org.testng.annotations.Test;
import ru.CryptoPro.CAdES.CAdESSignature;
import ru.CryptoPro.CAdES.CAdESSigner;

import java.security.SignatureException;
import java.security.cert.X509Certificate;

import static my.Constants.*;

public class DocumentSignerTest {

	@Test
	public void testSignCryptoPro() throws SignatureException {
		DocumentSigner signer = new DocumentSigner(IKARPOV_KEY_ALIAS, IKARPOV_KEY_PASS, CRYPTOPRO_TSA_URL);
		byte[] sign = signer.sign(ACT);

		SignatureVerifier verifier = new SignatureVerifier();
		CAdESSignature signature = verifier.verify(sign);

		Assert.assertEquals(signature.getCAdESSignerInfos().length, 1);
		Assert.assertTrue(hasSigner(signature, IKARPOV_CERT));
	}

	@Test
	public void testSignInfotecsByTest2012Cert() throws SignatureException {
		DocumentSigner signer = new DocumentSigner(TEST2012_KEY_ALIAS, TEST2012_KEY_PASS, INFOTECS_TSA_URL);
		byte[] sign = signer.sign(ACT);

		SignatureVerifier verifier = new SignatureVerifier();
		CAdESSignature signature = verifier.verify(sign);

		Assert.assertEquals(signature.getCAdESSignerInfos().length, 1);
		Assert.assertTrue(hasSigner(signature, TEST2012_CERT));
	}

	@Test
	public void testSignInfotecsByTestQiwi2012Cert() throws SignatureException {
		DocumentSigner signer = new DocumentSigner(TEST_QIWI_2012_KEY_ALIAS, TEST_QIWI_2012_KEY_PASS, INFOTECS_TSA_URL);
		byte[] sign = signer.sign(ACT);

		SignatureVerifier verifier = new SignatureVerifier();
		CAdESSignature signature = verifier.verify(sign);

		Assert.assertEquals(signature.getCAdESSignerInfos().length, 1);
		Assert.assertTrue(hasSigner(signature, TEST_QIWI_2012_CERT));
	}

	@Test
	public void testSignInfotecsTest2012Cryptopro() throws SignatureException {
		DocumentSigner infoSigner = new DocumentSigner(TEST2012_KEY_ALIAS, TEST2012_KEY_PASS, INFOTECS_TSA_URL);
		byte[] sign = infoSigner.sign(ACT);

		DocumentSigner cryptSigner = new DocumentSigner(IKARPOV_KEY_ALIAS, IKARPOV_KEY_PASS, CRYPTOPRO_TSA_URL);
		sign = cryptSigner.coSign(sign, ACT);

		SignatureVerifier verifier = new SignatureVerifier();
		CAdESSignature signature = verifier.verify(sign);

		Assert.assertEquals(signature.getCAdESSignerInfos().length, 2);
		Assert.assertTrue(hasSigner(signature, TEST2012_CERT));
		Assert.assertTrue(hasSigner(signature, IKARPOV_CERT));
	}

	@Test
	public void testDetachedInfotecsByTest2012Cert() throws SignatureException {
		DocumentSigner signer = new DocumentSigner(TEST2012_KEY_ALIAS, TEST2012_KEY_PASS, INFOTECS_TSA_URL, true);
		byte[] sign = signer.sign(ACT);

		SignatureVerifier verifier = new SignatureVerifier(ACT);
		CAdESSignature signature = verifier.verify(sign);

		Assert.assertEquals(signature.getCAdESSignerInfos().length, 1);
		Assert.assertTrue(hasSigner(signature, TEST2012_CERT));
	}

	@Test
	public void testDetachedInfotecsTest2012Cryptopro() throws SignatureException {
		DocumentSigner infoSigner = new DocumentSigner(TEST2012_KEY_ALIAS, TEST2012_KEY_PASS, INFOTECS_TSA_URL, true);
		byte[] sign = infoSigner.sign(ACT);

		DocumentSigner cryptSigner = new DocumentSigner(IKARPOV_KEY_ALIAS, IKARPOV_KEY_PASS, CRYPTOPRO_TSA_URL, true);
		sign = cryptSigner.coSign(sign, ACT);

		SignatureVerifier verifier = new SignatureVerifier(ACT);
		CAdESSignature signature = verifier.verify(sign);

		Assert.assertEquals(signature.getCAdESSignerInfos().length, 2);
		Assert.assertTrue(hasSigner(signature, TEST2012_CERT));
		Assert.assertTrue(hasSigner(signature, IKARPOV_CERT));
	}

	@Test
	public void testDetachedInfotecsByVorobyaninovCert() throws SignatureException {
		DocumentSigner signer = new DocumentSigner(VOROBYANINOV_KEY_ALIAS, VOROBYANINOV_KEY_PASS, "http://91.244.183.61/TSP/tsp.srf", true);
		byte[] sign = signer.sign(ACT);

		SignatureVerifier verifier = new SignatureVerifier(ACT);
		CAdESSignature signature = verifier.verify(sign);

		Assert.assertEquals(signature.getCAdESSignerInfos().length, 1);
		Assert.assertTrue(hasSigner(signature, VOROBYANINOV_CERT));
	}

	private boolean hasSigner(CAdESSignature signature, X509Certificate signerCert) {
		for (CAdESSigner signer : signature.getCAdESSignerInfos()) {
			if (signerCert.equals(signer.getSignerCertificate())) {
				return true;
			}
		}
		return false;
	}
}