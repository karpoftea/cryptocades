package my.store;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;

public class DefaultKeyStore {

	public KeyStore load() throws NoSuchProviderException, KeyStoreException,
			IOException, NoSuchAlgorithmException, CertificateException {
		KeyStore keyStore = KeyStore.getInstance("JKS", "SUN");
		InputStream is = getDefaultInputStream();
		try {
			keyStore.load(is, getDefaultPassword());
		} finally {
			is.close();
		}
		return keyStore;
	}

	private InputStream getDefaultInputStream() throws FileNotFoundException {
		return new FileInputStream(getStoragePath());
	}

	String getStoragePath() {
		return  System.getProperty("java.home") + File.separatorChar +
				"lib" + File.separatorChar +
				"security" + File.separatorChar +
				"cacerts";
	}

	public char[] getDefaultPassword() {
		return "changeit".toCharArray();
	}
}
