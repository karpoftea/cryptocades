package my;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public final class Constants {

	public static final String IKARPOV_KEY_ALIAS = "ikarpov_t1";
	public static final char[] IKARPOV_KEY_PASS = "qwerty".toCharArray();
	public static final X509Certificate IKARPOV_CERT = generate(FileUtil.resourceBytes(Constants.class, "I.Karpov_t1.cer"));

	public static final String TEST2012_KEY_ALIAS = "Test-2012";
	public static final char[] TEST2012_KEY_PASS = "qwerty".toCharArray();
	public static final X509Certificate TEST2012_CERT = generate(FileUtil.resourceBytes(Constants.class, "Test_2012.cer"));

	public static final String TEST_QIWI_2012_KEY_ALIAS = "Test_Qiwi_2012";
	public static final char[] TEST_QIWI_2012_KEY_PASS = "qwerty".toCharArray();
	public static final X509Certificate TEST_QIWI_2012_CERT = generate(FileUtil.resourceBytes(Constants.class, "Test_Qiwi_2012.cer"));

	public static final String CRYPTOPRO_TSA_URL = "http://www.cryptopro.ru/tsp/tsp.srf";
	public static final String INFOTECS_TSA_URL = "http://193.232.60.72:8777/tsp";

	public static final byte[] ACT = FileUtil.resourceBytes(Constants.class, "act_example.pdf");


	public static X509Certificate generate(byte[] cert) {
		try {
			return (X509Certificate) CertificateFactory.getInstance("X509").generateCertificate(new ByteArrayInputStream(cert));
		} catch (CertificateException e) {
			throw new RuntimeException(e);
		}
	}
}