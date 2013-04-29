package my.checker;

import com.google.common.base.Splitter;
import my.FileUtil;
import my.certificate.CertificateUtils;
import my.certificate.SimpleCertPathBuilder;
import my.store.CryptoproKeyStore;
import my.store.DefaultKeyStore;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;


public class JVMCryptoChecker {

	private final static Logger log = Logger.getLogger(JVMCryptoChecker.class.getName());


	public static void main(String[] args) {
		log.info("Starting checker app");

		JVMCryptoChecker app = new JVMCryptoChecker();
		CryptoCheckerReport report = app.check(args);
		log.info("Check completed, results:" + report);

		System.exit(report.hasErrors() ? 1 : 0);
	}

	private CryptoCheckerReport check(String[] cmdArgs) {
		Map<String, String> args = new ArgsMap(cmdArgs, flags);

		CryptoCheckerReport report = CryptoCheckerReport.empty();
		report.combine(checkMessageDigest())
			  .combine(checkSignature());

		if (args.containsKey(CONF)) {
			report.combine(checkPrivateKeys(args));
		}

		if (args.containsKey(CERT) || args.containsKey(CERT_DIR)) {
			report.combine(checkCertPath(args));
		}

		return report;
	}

	private CryptoCheckerReport checkPrivateKeys(Map<String, String> args) {
		CryptoCheckerReport report = CryptoCheckerReport.empty();
		Map<String, String> credentials;
		try {
			credentials = getCredentials(args.get(CONF));
		} catch (Exception e) {
			log.log(Level.SEVERE, "retrieving credentials exception", e);
			return CryptoCheckerReport.keyError(null, e);
		}

		for (Map.Entry<String, String> entry : credentials.entrySet()) {
			String alias = entry.getKey();
			try {
				Key key = getCryptoproKeyStore().getKey(alias, entry.getValue().toCharArray());
				report.combine(
						key != null ?
							CryptoCheckerReport.keySuccess(alias) :
							CryptoCheckerReport.keyError(alias, new Exception("key not found"))
				);
			} catch (Exception e) {
				log.log(Level.SEVERE, "certificate creating exception", e);
				report.combine(CryptoCheckerReport.keyError(alias, e));
			}
		}
		return report;
	}

	private Map<String, String> getCredentials(String fileName) throws Exception {
		String data = new String(PBE.decrypt("openthedoor".toCharArray(), readFile(fileName)));
		return Splitter.on(';').trimResults().omitEmptyStrings().withKeyValueSeparator(":").split(data);
	}

	byte[] readFile(String s) throws IOException {
		RandomAccessFile f = new RandomAccessFile(s, "r");
		byte[] b = new byte[(int)f.length()];
		f.read(b);
		return b;
	}

	private CryptoCheckerReport checkCertPath(Map<String, String> args) {
		String certFileName = args.get(CERT);
		String certDirName = args.get(CERT_DIR);
		if (isEmpty(certFileName) && isEmpty(certDirName)) {
			log.warning("Can't check certificate path because -cert and -certdir arguments are empty");
			return CryptoCheckerReport.certError(null, new Exception("certificate file name and directory is empty"));
		}

		CryptoCheckerReport report = CryptoCheckerReport.empty();

		List<X509CertBean> certificates = new ArrayList<X509CertBean>();
		if (!isEmpty(certFileName)) {
			X509CertBean certBean = new X509CertBean(certFileName);
			try {
				certBean.setCertificate(toX509Certificate(certBean.getFileName()));
				certificates.add(certBean);
			} catch (Exception e) {
				log.log(Level.SEVERE, "certificate creating exception", e);
				report.combine(CryptoCheckerReport.certError(certBean, e));
			}
		}

		if (!isEmpty(certDirName)) {
			File dir = new File(certDirName);
			if (!dir.isDirectory()) {
				report.combine(CryptoCheckerReport.certError(null, new Exception('\'' + certDirName + "' is not a directory")));
			} else {
				for (File file : dir.listFiles()) {
					X509CertBean certBean = new X509CertBean(file.getName());
					try {
						certBean.setCertificate(toX509Certificate(file.getAbsolutePath()));
						certificates.add(certBean);
					} catch (Exception e) {
						log.log(Level.SEVERE, "certificate creating exception", e);
						report.combine(CryptoCheckerReport.certError(certBean, e));
					}
				}
			}
		}

		if (certificates.isEmpty()) {
			return report;
		}

		KeyStore defaultKeyStore;
		try {
			defaultKeyStore = getDefaultKeyStore();
		} catch (Exception e) {
			log.log(Level.SEVERE, "key store creating exception", e);
			return report.combine(CryptoCheckerReport.certError(null, e));
		}

		for (X509CertBean certBean : certificates) {
			try {
				SimpleCertPathBuilder pathBuilder = new SimpleCertPathBuilder(defaultKeyStore);
				pathBuilder.buildCertPath(certBean.getCertificate());
				report.combine(CryptoCheckerReport.certPathSuccess(certBean));
			} catch (Exception e) {
				log.log(Level.SEVERE, "certBean path building exception", e);
				report.combine(CryptoCheckerReport.certError(certBean, e)) ;
			}
		}
		return report;
	}

	private X509Certificate toX509Certificate(String fileName) throws CertificateException, IOException {
		return CertificateUtils.toX509Certificate(FileUtil.readFile(fileName));
	}

	private boolean isEmpty(String certFileName) {
		return certFileName == null || certFileName.isEmpty();
	}

	private KeyStore getCryptoproKeyStore() throws NoSuchProviderException, KeyStoreException,
			IOException, NoSuchAlgorithmException, CertificateException {
		return new CryptoproKeyStore().load();
	}

	private KeyStore getDefaultKeyStore() throws NoSuchProviderException, KeyStoreException,
			IOException, NoSuchAlgorithmException, CertificateException {
		return new DefaultKeyStore().load();
	}


	private CryptoCheckerReport checkMessageDigest() {
		log.info("Checking message digest");

		CryptoCheckerReport mdReport = CryptoCheckerReport.empty();
		mdReport.combine(createMessageDigest("SHA-256", "SUN"))
				.combine(createMessageDigest("GOST3411", "JCP"));

		log.info("Checking message digest completed");

		return mdReport;
	}

	private CryptoCheckerReport checkSignature() {
		log.info("Checking digital signature");

		CryptoCheckerReport signatureReport = createGost3411Signature();

		log.info("Checking digital signature completed");
		return signatureReport;
	}

	private CryptoCheckerReport createGost3411Signature() {
		log.info("Creating GOST3411 signature");

		String algName = "GOST3411withGOST3410EL";
		String prvName = "JCP";
		try {
			KeyPair keyPair = generateKeyPair("GOST3410EPH", prvName);
			createDigitalSignature(keyPair.getPrivate(), algName, prvName);

			log.info("Creating GOST3411 signature OK");
			return CryptoCheckerReport.signature(algName, prvName);
		} catch (Exception e) {
			log.log(Level.SEVERE, "signature creation error", e);
			return CryptoCheckerReport.signatureError(algName, prvName, e);
		}
	}

	private void createDigitalSignature(PrivateKey key, String algName, String prvName)
			throws NoSuchProviderException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
		Signature signature = Signature.getInstance(algName, prvName);
		signature.initSign(key);
		signature.update(DATA.getBytes());
		signature.sign();
	}

	private static KeyPair generateKeyPair(String algName, String prvName)
			throws NoSuchProviderException, NoSuchAlgorithmException {
		KeyPairGenerator generator = KeyPairGenerator.getInstance(algName, prvName);
		return generator.generateKeyPair();
	}

	private CryptoCheckerReport createMessageDigest(String algName, String prvName) {
		log.info("Creating hash for alg:" + algName + " prvName:" + prvName);
		try {
			MessageDigest md = MessageDigest.getInstance(algName, prvName);
			md.digest(DATA.getBytes());

			log.info("Creating hash for alg:" + algName + " prvName:" + prvName + " OK");
			return CryptoCheckerReport.digestSuccess(algName, prvName);
		} catch (Exception e) {
			log.log(Level.SEVERE, "error creating message digest", e);
			return CryptoCheckerReport.digestError(algName, prvName, e);
		}
	}


	private static final String DATA = "very secret data";
	static final String CERT = "-cert";
	static final String CERT_DIR = "-certdir";
	static final String CONF = "-conf";

	static final Map<String, Pattern> flags = new HashMap<String, Pattern>();
	static {
		flags.put(CERT, Pattern.compile(".*"));
		flags.put(CERT_DIR, Pattern.compile(".*"));
		flags.put(CONF, Pattern.compile(".*"));
	}
}