package my.ocsa;

import my.transport.HttpClientFacade;
import my.transport.RequestParameters;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPReq;
import org.bouncycastle.ocsp.OCSPReqGenerator;
import org.bouncycastle.ocsp.OCSPResp;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertificateException;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Vector;

public class OCSAClient {

	private final X509Certificate issuer;
	private final X509Certificate cert;
	private final String ocsaUrl;

	public OCSAClient(X509Certificate cert) throws SecurityException, CertificateException {
		this.cert = cert;
		this.issuer = getIssuer(cert);
		this.ocsaUrl = extractOCSAUrl(cert);
	}

	public OCSAClient(X509Certificate issuer, X509Certificate cert, String ocsaUrl) {
		this.cert = cert;
		this.issuer = issuer;
		this.ocsaUrl = ocsaUrl;
	}

	public OCSAClient(X509Certificate cert, String ocsaUrl) {
		this.cert = cert;
		this.issuer = getIssuer(cert);
		this.ocsaUrl = ocsaUrl;
	}

	public OCSAClient(X509Certificate issuer, X509Certificate cert) throws CertificateException {
		this.cert = cert;
		this.issuer = issuer;
		this.ocsaUrl = extractOCSAUrl(cert);
	}


	public OCSPResp call() {
		OCSPReq request = createRequest();
		return callOCSA(request);
	}

	private OCSPResp callOCSA(OCSPReq request) {
		try {
			byte[] response = HttpClientFacade.createClient(createRequestParams(request)).call();
			return new OCSPResp(response);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	private RequestParameters createRequestParams(OCSPReq request) throws IOException {
		RequestParameters params = new RequestParameters();
		params.setUrl(ocsaUrl);
		params.setContentType("application/ocsp-request");
		params.setAcceptType("application/ocsp-response");
		params.setMethod("POST");
		params.setData(request.getEncoded());
		return params;
	}

	private OCSPReq createRequest() {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		try {
			CertificateID id = new CertificateID(CertificateID.HASH_SHA1, issuer, cert.getSerialNumber());

			Vector oids = new Vector();
			oids.add(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);

			Vector values = new Vector();
			BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());
			values.add(new X509Extension(false, new DEROctetString(nonce.toByteArray())));

			OCSPReqGenerator gen = new OCSPReqGenerator();
			gen.addRequest(id);
			gen.setRequestExtensions(new X509Extensions(oids, values));
			return gen.generate();
		} catch (OCSPException e) {
			throw new RuntimeException(e);
		}
	}

	private X509Certificate getIssuer(X509Certificate cert) {
		PKIXCertPathBuilderResult result = buildCertPath(cert);
		List<X509Certificate> certificates = (List<X509Certificate>)result.getCertPath().getCertificates();
		return certificates.size() == 1 ?
				certificates.iterator().next() :
				result.getTrustAnchor().getTrustedCert();
	}

	private PKIXCertPathBuilderResult buildCertPath(X509Certificate cert) {
		try {
			KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
			try {
				store.load(new FileInputStream(getDefaultTrustedCertStorePath()), getDefaultTrustedCertStorePassword());

				X509CertSelector selector = new X509CertSelector();
				selector.setCertificate(cert);

				PKIXBuilderParameters pkixParams = new PKIXBuilderParameters(store, selector);
				pkixParams.setRevocationEnabled(false);
				return (PKIXCertPathBuilderResult) CertPathBuilder.getInstance("PKIX", "SUN").build(pkixParams);
			} finally {
				store.store(new FileOutputStream(getDefaultTrustedCertStorePath()), getDefaultTrustedCertStorePassword());
			}
		} catch (CertPathBuilderException e) {
			StringBuilder sb = new StringBuilder
					 ("\n Unable to build chain for certificate {" + cert.getSerialNumber().toString(16) + "}");
			sb.append("\n To resolve this situation:");
			sb.append("\n 1) use another constructor");
			sb.append("\n 2) add certificates to trusted store(aka cacerts, jssecerts) to build valid chain");
			sb.append("\n\n Stacktrace:");
			throw new RuntimeException(sb.toString(), e);
		}catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	private char[] getDefaultTrustedCertStorePassword() {
		return "changeit".toCharArray();
	}

	private String getDefaultTrustedCertStorePath() {
		return System.getProperty("java.home") + File.separatorChar +
			   "lib" + File.separatorChar +
			   "security" + File.separatorChar +
			   "cacerts";
	}

	private String extractOCSAUrl(X509Certificate cert) throws CertificateException {
		try {
			ASN1Object extensionDer = DEROctetString.fromByteArray(cert.getExtensionValue(X509Extension.authorityInfoAccess.toString()));
			if (extensionDer == null) {
				throw new CertificateException("certificate [" + cert.getSerialNumber() + "] has no AIA extension oid={" + X509Extension.authorityInfoAccess.toString() + "}");
			}

			AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(new X509Extension(false, (DEROctetString) extensionDer));
			for (AccessDescription accessDescription : aia.getAccessDescriptions()) {
				if (AccessDescription.id_ad_ocsp.equals(accessDescription.getAccessMethod())) {
					return accessDescription.getAccessLocation().getName().toString();
				}
			}

			throw new CertificateException("certificate [" + cert.getSerialNumber() + "] AIA extension has no entry of OCSA oid={" + AccessDescription.id_ad_ocsp.toString() + "}");
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}
}