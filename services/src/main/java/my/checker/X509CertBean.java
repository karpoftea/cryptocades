package my.checker;

import java.security.cert.X509Certificate;

class X509CertBean {

	private final String fileName;
	private X509Certificate certificate;

	X509CertBean(String fileName) {
		this.fileName = fileName;
	}

	String getFileName() {
		return fileName;
	}

	X509Certificate getCertificate() {
		return certificate;
	}

	public void setCertificate(X509Certificate certificate) {
		this.certificate = certificate;
	}
}