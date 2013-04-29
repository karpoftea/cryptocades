package my.checker;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class CryptoCheckerReport {

	private final Map<OperationType, List<Success>> successes = new HashMap<OperationType, List<Success>>();
	private final Map<OperationType, List<Error>> errors = new HashMap<OperationType, List<Error>>();

	private CryptoCheckerReport() {}

	public static CryptoCheckerReport empty() {
		return new CryptoCheckerReport();
	}

	public Map<OperationType, List<Error>> getErrors() {
		return errors;
	}

	public Map<OperationType, List<Success>> getSuccesses() {
		return successes;
	}

	public boolean hasErrors() {
		return countErrors() != 0;
	}

	public CryptoCheckerReport combine(CryptoCheckerReport report) {
		putAll(successes, report.getSuccesses());
		putAll(errors, report.getErrors());
		return this;
	}

	private <T> void putAll(Map<OperationType, List<T>> original, Map<OperationType, List<T>> additional) {
		for (OperationType type : OperationType.values()) {
			List<T> origList = original.get(type);
			List<T> additionalList = additional.get(type);
			if (origList == null) {
				if (additionalList != null) {
					original.put(type, additionalList);
				}
			} else {
				if (additionalList != null) {
					origList.addAll(additionalList);
				}
			}
		}
	}


	static CryptoCheckerReport signature(String algName, String prvName) {
		return empty().addSuccess(OperationType.SIGNATURE, new CryptoActionDigestSuccess(algName, prvName));
	}

	static CryptoCheckerReport digestSuccess(String algName, String prvName) {
		return empty().addSuccess(OperationType.DIGEST, new CryptoActionDigestSuccess(algName, prvName));
	}

	static CryptoCheckerReport certPathSuccess(X509CertBean certificate) {
		return empty().addSuccess(OperationType.CERT_PATH, new CertSuccess(certificate));
	}

	static CryptoCheckerReport keySuccess(String keyAlias) {
		return empty().addSuccess(OperationType.PRIVATE_KEY, new KeySuccess(keyAlias));
	}

	static CryptoCheckerReport digestError(String algName, String prvName, Exception e) {
		return empty().addError(OperationType.DIGEST, new CryptoActionError(e, algName, prvName));
	}

	static CryptoCheckerReport signatureError(String algName, String prvName, Exception e) {
		return empty().addError(OperationType.SIGNATURE, new CryptoActionError(e, algName, prvName));
	}

	static CryptoCheckerReport certError(X509CertBean certBean, Exception e) {
		return empty().addError(OperationType.CERT_PATH, new CertError(e, certBean));
	}

	static CryptoCheckerReport keyError(String keyAlias, Exception e) {
		return empty().addError(OperationType.PRIVATE_KEY, new KeyError(e, keyAlias));
	}

	CryptoCheckerReport addError(OperationType operationType, Error error) {
		add(operationType, error, errors);
		return this;
	}

	CryptoCheckerReport addSuccess(OperationType operationType, Success success) {
		add(operationType, success, successes);
		return this;
	}

	private int countErrors() {
		return countTotal(errors);
	}

	private int countSuccesses() {
		return countTotal(successes);
	}

	private <T, V> int countTotal(Map<T, List<V>> container) {
		int num = 0;
		if (container.isEmpty()) {
			return num;
		}
		for (List<V> errors : container.values()) {
			num += errors != null ? errors.size() : 0;
		}
		return num;
	}


	<T> void add(OperationType operationType, T obj, Map<OperationType, List<T>> container) {
		List<T> list = container.get(operationType);
		if (list == null) {
			container.put(operationType, list = new ArrayList<T>());
		}
		list.add(obj);
	}

	@Override
	public String toString() {
		int successes = countSuccesses();
		int errors = countErrors();

		StringBuilder sb =
			new StringBuilder("\n---------REPORT--------\n")
				.append("total tests:").append(successes + errors)
				.append(", success:").append(successes)
				.append(", errors:").append(errors).append("\n");

		if (successes != 0) {
			sb.append("----Succeeded tests----\n").append(list(this.successes)).append("\n");
		}
		if (errors != 0) {
			sb.append("----Failed tests----\n").append(list(this.errors)).append("\n");
		}

		return sb.toString();
	}

	private <T> String list(Map<OperationType, List<T>> container) {
		StringBuilder sb = new StringBuilder();
		for (Map.Entry<OperationType, List<T>> entry : container.entrySet()) {
			sb.append(entry.getKey()).append(": ").append(list(entry.getValue())).append("\n");
		}
		return sb.toString();
	}

	private <T> String list(List<T> value) {
		StringBuilder sb = new StringBuilder("[\n");
		for(Iterator<T> iter = value.iterator(); iter.hasNext();) {
			sb.append(iter.next()).append(iter.hasNext() ? "\n" : "\n]");
		}
		return sb.toString();
	}

	enum OperationType {
		DIGEST, SIGNATURE, CERT_PATH, PRIVATE_KEY;
	}

	private static class CertError extends Error {
		private final X509CertBean certBean;

		private CertError(Exception e, X509CertBean certBean) {
			super(e);
			this.certBean = certBean;
		}

		@Override
		public String toString() {
			return "[certificate=" + (certBean == null ? "null" : print()) + "]";
		}

		private String print() {
			X509Certificate certificate = certBean.getCertificate();
			return new StringBuilder("{")
					.append("fileName:").append(certBean.getFileName()).append(", ")
					.append("exception:").append(e.getMessage())
					.append(certificate == null ? "" : (", " + printCertInfo(certificate)))
					.append("}")
					.toString();
		}

		private String printCertInfo(X509Certificate certificate) {
			return new StringBuffer("sn:")
					.append(getSerialNumber(certificate)).append(", ")
					.append("subject:").append(certificate.getSubjectX500Principal())
					.toString();
		}

		private String getSerialNumber(X509Certificate certificate) {
			return certificate.getSerialNumber().toString(16).toUpperCase();
		}
	}

	private static class KeyError extends Error {
		private final String keyAlias;

		private KeyError(Exception e, String keyAlias) {
			super(e);
			this.keyAlias = keyAlias;
		}

		@Override
		public String toString() {
			return "[keyAlias=" + keyAlias + ", error=" + e.getMessage() + "]";
		}
	}

	private static class CryptoActionError extends Error {
		private final String algName;
		private final String prvName;

		private CryptoActionError(Exception e, String algName, String prvName) {
			super(e);
			this.algName = algName;
			this.prvName = prvName;
		}

		@Override
		public String toString() {
			return "[algName='" + algName + '\'' + ", prvName='" + prvName + '\'' + ", exception=" + e.getMessage() + "]";
		}
	}

	private abstract static class Error {
		protected final Exception e;

		private Error(Exception e) {
			this.e = e;
		}
	}


	private static abstract class Success {}

	private static class CertSuccess extends Success {
		private final X509CertBean certificate;

		private CertSuccess(X509CertBean certificate) {
			this.certificate = certificate;
		}

		@Override
		public String toString() {
			return "[certificate=" + (certificate == null ? "null" : print(certificate)) + "]";
		}

		private String print(X509CertBean bean) {
			X509Certificate certificate = bean.getCertificate();
			return new StringBuilder("{")
					.append("fileName:").append(bean.getFileName()).append(", ")
					.append("sn:").append(getSerialNumber(certificate)).append(", ")
					.append("subject:").append(certificate.getSubjectX500Principal()).append("}")
					.toString();
		}

		private String getSerialNumber(X509Certificate certificate) {
			return certificate.getSerialNumber().toString(16).toUpperCase();
		}
	}

	private static class CryptoActionDigestSuccess extends Success {
		private final String algName;
		private final String prvName;

		private CryptoActionDigestSuccess(String algName, String prvName) {
			this.algName = algName;
			this.prvName = prvName;
		}

		@Override
		public String toString() {
			return "[algName='" + algName + '\'' + ", prvName='" + prvName + "\']";
		}
	}

	private static class KeySuccess extends Success {
		private final String keyAlias;

		private KeySuccess(String keyAlias) {
			this.keyAlias = keyAlias;
		}

		@Override
		public String toString() {
			return "[keyAlias=" + keyAlias + "]";
		}
	}
}
