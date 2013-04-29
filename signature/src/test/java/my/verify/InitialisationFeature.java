package my.verify;

import my.Constants;
import my.FileUtil;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.ocsp.OCSPException;
import ru.CryptoPro.CAdES.CAdESSignature;
import ru.CryptoPro.CAdES.CAdESSigner;
import ru.CryptoPro.CAdES.CAdESType;
import ru.CryptoPro.CAdES.exception.CAdESException;

import java.io.IOException;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertStoreException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.ParseException;

public class InitialisationFeature {

	public static void main(String[] args) throws CAdESException, NoSuchProviderException, CMSException, NoSuchAlgorithmException, SignatureException, OCSPException, CertStoreException, IOException, CRLException, ParseException, CertificateException {
		byte[] sign = FileUtil.resourceBytes(InitialisationFeature.class, "infotecs_test_2012_and_cryptopro_cades_api_gen.sig");
		CAdESSignature signature = new CAdESSignature(sign, Constants.ACT, CAdESType.CAdES_X_Long_Type_1);

		printSigners(signature, System.out);

		signature.verify(null);
		printSigners(signature, System.out);
	}

	static void printSigners(CAdESSignature signature, OutputStream os) throws SignatureException {
		StringBuilder sb = new StringBuilder("Signers:\n");
		CAdESSigner[] cAdESSignerInfos = signature.getCAdESSignerInfos();
		for (CAdESSigner signer : cAdESSignerInfos) {
			X509Certificate certificate = signer.getSignerCertificate();
			sb.append(" sn:").append(certificate == null ? "null" : certificate.getSerialNumber())
					.append(" subject:").append(certificate == null ? "null" : certificate.getSubjectDN().getName())
					.append(" \n");
		}

		try {
			os.write(sb.toString().getBytes());
		} catch (IOException e) {
			throw new SignatureException(e);
		}
	}
}
