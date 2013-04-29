package my.verify;

import ru.CryptoPro.CAdES.CAdESSignature;
import ru.CryptoPro.CAdES.CAdESSigner;
import ru.CryptoPro.CAdES.CAdESType;

import java.io.IOException;
import java.io.OutputStream;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.Collection;

public class SignatureVerifier {

	private byte[] data;

	public SignatureVerifier() {
	}

	public SignatureVerifier(byte[] data) {
		this.data = data;
	}

	public CAdESSignature verify(byte[] sign) throws SignatureException {
		try {
			CAdESSignature signature = new CAdESSignature(sign, data, CAdESType.CAdES_X_Long_Type_1);
			signature.verify(null);
			return signature;
		} catch (Exception e) {
			throw new SignatureException(e);
		}
	}

	@Deprecated
	public CAdESSignature verify(byte[] sign, Collection<X509Certificate> certs) throws SignatureException {
		try {
			CAdESSignature signature = new CAdESSignature(sign, data, CAdESType.CAdES_X_Long_Type_1);
			signature.verify(certs);
			return signature;
		} catch (Exception e) {
			throw new SignatureException(e);
		}
	}

	public void printSigners(CAdESSignature signature, OutputStream os) throws SignatureException {
		StringBuilder sb = new StringBuilder("Signers:\n");
		CAdESSigner[] signers = signature.getCAdESSignerInfos();
		for (CAdESSigner signer : signers) {
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
}