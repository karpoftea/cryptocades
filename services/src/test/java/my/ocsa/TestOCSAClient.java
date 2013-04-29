package my.ocsa;

import my.FileUtil;
import org.bouncycastle.ocsp.OCSPResp;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;


public class TestOCSAClient {

	@Test
	public void testCryptoProOCSA() throws CertificateException {
		OCSAClient ocsaClient = new OCSAClient(I_KARPOV_CERT, CPRO_ROOT, "http://www.cryptopro.ru/ocspnc/ocsp.srf");
		OCSPResp response = ocsaClient.call();
		Assert.assertEquals(response.getStatus(), 0);
	}

	@Test
	public void testInfotecs2011OCSA() throws CertificateException {
		OCSAClient ocsaClient = new OCSAClient(INFOTECS_ROOT_2011, CLIENTSIDE_OSMP_OCSP_TEST);
		OCSPResp response = ocsaClient.call();
		Assert.assertEquals(response.getStatus(), 0);
	}

	@Test
	public void testInfotecs2012OCSA() throws CertificateException {
		OCSAClient ocsaClient = new OCSAClient(TEST_QIWI_2012);
		OCSPResp response = ocsaClient.call();
		Assert.assertEquals(response.getStatus(), 0);
	}


	private static final X509Certificate I_KARPOV_CERT = FileUtil.readCertificate(TestOCSAClient.class, "I.Karpov_t1.cer");//cryptopro client cert
	private static final X509Certificate CLIENTSIDE_OSMP_OCSP_TEST = FileUtil.readCertificate(TestOCSAClient.class, "ClientSide OSMP_OCSP_TEST.cer");//infotecs client cert (2011)
	private static final X509Certificate TEST_QIWI_2012 = FileUtil.readCertificate(TestOCSAClient.class, "Test_Qiwi_2012.cer");//infotecs client cert (2012)

	private static final X509Certificate CPRO_ROOT = FileUtil.readCertificate(TestOCSAClient.class, "cpro_root.cer");//cryptopro root cert
	private static final X509Certificate INFOTECS_ROOT_2011 = FileUtil.readCertificate(TestOCSAClient.class, "infotecs_root_2011.cer");//infotecs root cert (2011)
}