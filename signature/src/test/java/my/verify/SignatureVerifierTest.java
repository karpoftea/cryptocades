package my.verify;

import my.Constants;
import my.FileUtil;
import org.bouncycastle.util.encoders.Base64;
import org.testng.Assert;
import org.testng.annotations.Test;
import ru.CryptoPro.CAdES.CAdESSignature;
import ru.CryptoPro.CAdES.CAdESSigner;

import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static my.Constants.ACT;
import static my.Constants.IKARPOV_CERT;
import static my.Constants.TEST2012_CERT;
import static my.Constants.TEST_QIWI_2012_CERT;

public class SignatureVerifierTest {

	@Test
	public void testStoredCryptoProSig() throws SignatureException {
		byte[] sign = FileUtil.resourceBytes(SignatureVerifierTest.class, "cryptopro_java_cades_api_gen.sig");
		CAdESSignature signature = new SignatureVerifier().verify(sign);

		Assert.assertEquals(signature.getCAdESSignerInfos().length, 1);
		Assert.assertTrue(hasSigner(signature, IKARPOV_CERT));
	}

	@Test
	public void testStoredInfotecsTest2012Sig() throws SignatureException {
		byte[] sign = FileUtil.resourceBytes(SignatureVerifierTest.class, "infotecs_test2012_cades_api_gen.sig");
		CAdESSignature signature = new SignatureVerifier().verify(sign);

		Assert.assertEquals(signature.getCAdESSignerInfos().length, 1);
		Assert.assertTrue(hasSigner(signature, TEST2012_CERT));
	}

	@Test
	public void testStoredInfotecsTestQiwi2012Sig() throws SignatureException {
		byte[] sign = FileUtil.resourceBytes(SignatureVerifierTest.class, "infotecs_test_qiwi_2012_cades_api_gen.sig");
		CAdESSignature signature = new SignatureVerifier().verify(sign);

		Assert.assertEquals(signature.getCAdESSignerInfos().length, 1);
		Assert.assertTrue(hasSigner(signature, TEST_QIWI_2012_CERT));
	}

	@Test
	public void testStoredInfotecsTestQiwi2012CryptoproSig() throws SignatureException {
		byte[] sign = FileUtil.resourceBytes(SignatureVerifierTest.class, "infotecs_test_2012_and_cryptopro_cades_api_gen.sig");
		CAdESSignature signature = new SignatureVerifier().verify(sign);

		Assert.assertEquals(signature.getCAdESSignerInfos().length, 2);
		Assert.assertTrue(hasSigner(signature, TEST2012_CERT));
		Assert.assertTrue(hasSigner(signature, IKARPOV_CERT));
	}

	@Test
	public void testStoredDetachedInfotecsTest2012Sig() throws SignatureException {
		byte[] sign = FileUtil.resourceBytes(SignatureVerifierTest.class, "infotecs_test2012_detached_java_cades_api_gen.sig");
		CAdESSignature signature = new SignatureVerifier(ACT).verify(sign);

		Assert.assertEquals(signature.getCAdESSignerInfos().length, 1);
		Assert.assertTrue(hasSigner(signature, TEST2012_CERT));
	}

	@Test
	public void testStoredDetachedInfotecsTest2012CryptoproSig() throws SignatureException {
		byte[] sign = FileUtil.resourceBytes(SignatureVerifierTest.class, "infotecs_test_2012_and_cryptopro_detached_cades_api_gen.sig");
		CAdESSignature signature = new SignatureVerifier(ACT).verify(sign);

		Assert.assertEquals(signature.getCAdESSignerInfos().length, 2);
		Assert.assertTrue(hasSigner(signature, TEST2012_CERT));
		Assert.assertTrue(hasSigner(signature, IKARPOV_CERT));
	}

	@Test(groups = "plugin-test")
	public void testBrowserTest2012Sig() throws SignatureException {
		byte[] sign = Base64.decode(FileUtil.resourceBytes(SignatureVerifierTest.class, "browser_test2012.sig.b64"));
		byte[] data = Base64.decode(FileUtil.resourceBytes(SignatureVerifierTest.class, "data.txt.b64"));
		CAdESSignature signature = new SignatureVerifier(data).verify(sign);

		Assert.assertEquals(signature.getCAdESSignerInfos().length, 1);
		Assert.assertTrue(hasSigner(signature, TEST2012_CERT));
	}

	@Test(groups = "plugin-test")
	public void testBrowserTest2012AndCryptoproSig() throws SignatureException {
		byte[] sign = Base64.decode(FileUtil.resourceBytes(SignatureVerifierTest.class, "browser_test2012_and_cryptopro.sig.b64"));
		byte[] data = Base64.decode(FileUtil.resourceBytes(SignatureVerifierTest.class, "data.txt.b64"));
		CAdESSignature signature = new SignatureVerifier(data).verify(sign);

		Assert.assertEquals(signature.getCAdESSignerInfos().length, 2);
		Assert.assertTrue(hasSigner(signature, TEST2012_CERT));
		Assert.assertTrue(hasSigner(signature, IKARPOV_CERT));
	}

	@Test
	public void testQiwiCadesSig() throws SignatureException, CertificateException {
		byte[] sign = FileUtil.resourceBytes(SignatureVerifierTest.class, "act_346952_29.02.2012.sig");
		byte[] data = FileUtil.resourceBytes(SignatureVerifierTest.class, "act_346952_29.02.2012.pdf");

		X509Certificate lisicinaCert = Constants.generate(FileUtil.resourceBytes(SignatureVerifierTest.class, "Lisicina_2012.cer"));

		CAdESSignature signature = new SignatureVerifier(data).verify(sign);
		Assert.assertEquals(signature.getCAdESSignerInfos().length, 2);
		Assert.assertTrue(hasSigner(signature, lisicinaCert));
		Assert.assertTrue(hasSigner(signature, TEST2012_CERT));
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