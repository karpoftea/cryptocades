package my.verify;

import my.FileUtil;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.ocsp.OCSPException;
import ru.CryptoPro.CAdES.CAdESSignature;
import ru.CryptoPro.CAdES.CAdESType;
import ru.CryptoPro.CAdES.exception.CAdESException;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CRLException;
import java.security.cert.CertStoreException;
import java.security.cert.CertificateException;
import java.text.ParseException;

public class QiwiVsCryptoCadesBugReport {

	public static void main(String[] args)
			throws OCSPException, CAdESException, CertStoreException, IOException, CRLException, NoSuchProviderException, ParseException,
			CertificateException, CMSException, NoSuchAlgorithmException {

		byte[] sign = FileUtil.resourceBytes(QiwiVsCryptoCadesBugReport.class, "act_346952_29.02.2012.sig");
		byte[] data = FileUtil.resourceBytes(QiwiVsCryptoCadesBugReport.class, "act_346952_29.02.2012.pdf");

		CAdESSignature signature = new CAdESSignature(sign, data, CAdESType.CAdES_X_Long_Type_1);
		signature.verify(null);
	}
}
