package my.tsa;

import my.transport.HttpClientFacade;
import my.transport.RequestParameters;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;

import java.io.IOException;
import java.math.BigInteger;

public class TSAClient {

	private final byte[] imprint;
	private final String tsaUrl;
	private final boolean validate;

	public TSAClient(byte[] imprint, String tsaUrl, boolean validate) {
		this.imprint = imprint;
		this.tsaUrl = tsaUrl;
		this.validate = validate;
	}

	public TSAClient(byte[] imprint, String tsaUrl) {
		this(imprint, tsaUrl, false);
	}

	public TimeStampResponse call() {
		TimeStampRequest request = createRequest();
		return callTSA(request);
	}

	private TimeStampResponse callTSA(TimeStampRequest request) {
		try {
			TimeStampResponse response = new TimeStampResponse(HttpClientFacade.createClient(createRequestParams(request)).call());
			if (validate) {
				response.validate(request);
			}
			return response;
		} catch (TSPException e) {
			throw new RuntimeException(e);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	private RequestParameters createRequestParams(TimeStampRequest request) throws IOException {
		RequestParameters params = new RequestParameters();
		params.setUrl(tsaUrl);
		params.setContentType("application/timestamp-query");
		params.setAcceptType("application/timestamp-query");
		params.setMethod("POST");
		params.setData(request.getEncoded());
		return params;
	}

	private TimeStampRequest createRequest() {
		TimeStampRequestGenerator generator = new TimeStampRequestGenerator();
		generator.setCertReq(true);
		return generator.generate("1.2.643.2.2.9", imprint, BigInteger.valueOf(System.currentTimeMillis()));
	}
}