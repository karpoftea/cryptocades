package my.certificate;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class CertificateUtils {

	public static X509Certificate toX509Certificate(byte[] data) throws CertificateException {
		CertificateFactory cf = CertificateFactory.getInstance("X509");
		return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(data));
	}
}