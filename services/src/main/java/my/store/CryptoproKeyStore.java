package my.store;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;

public class CryptoproKeyStore {

	public KeyStore load()
			throws NoSuchProviderException, KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
		KeyStore keyStore = KeyStore.getInstance("HDImageStore", "JCP");
		keyStore.load(null);
		return keyStore;
	}
}