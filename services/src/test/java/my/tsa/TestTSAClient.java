package my.tsa;

import org.bouncycastle.tsp.TimeStampResponse;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class TestTSAClient {

	@Test
	public void testCryptoProTSA() throws NoSuchProviderException, NoSuchAlgorithmException {
		TSAClient tsaClient = new TSAClient(createGOST3211Imprint(), CRYPTOPRO_TSA_URL);
		TimeStampResponse response = tsaClient.call();
		Assert.assertEquals(response.getStatus(), 0);
	}

	@Test
	public void testInfotecsTSA() throws NoSuchProviderException, NoSuchAlgorithmException {
		TSAClient tsaClient = new TSAClient(createGOST3211Imprint(), INFOTECS_TSA_URL);
		TimeStampResponse response = tsaClient.call();
		Assert.assertEquals(response.getStatus(), 0);
	}

	private byte[] createGOST3211Imprint() throws NoSuchAlgorithmException, NoSuchProviderException {
		MessageDigest md = MessageDigest.getInstance("GOST3411", "JCP");
		return md.digest("this is signature value".getBytes());
	}


	private static final String CRYPTOPRO_TSA_URL = "http://www.cryptopro.ru/tsp/tsp.srf";
	private static final String INFOTECS_TSA_URL = "http://193.232.60.72:8777/tsp";
}