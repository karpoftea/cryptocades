package my.transport;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

/** @author i.karpov */
public class SimpleHttpClient implements HttpClient {

	private final RequestParameters params;

	public SimpleHttpClient(RequestParameters params) {
		this.params = params;
	}

	@Override
	public byte[] call() throws IOException {
		HttpURLConnection c = doRequest();
		return recieveResponse(c);
	}

	private HttpURLConnection doRequest() throws IOException {
		HttpURLConnection c = (HttpURLConnection) new URL(params.getUrl()).openConnection();
		c.setDoOutput(true);
		c.setDoInput(true);
		c.setRequestMethod(params.getMethod());
		c.setRequestProperty("Content-type", params.getContentType());
		c.setRequestProperty("Accept", params.getAcceptType());
		c.setRequestProperty("Content-length", String.valueOf(params.getData().length));

		OutputStream out = c.getOutputStream();
		try {
			out.write(params.getData());
			out.flush();
		} finally {
			out.close();
		}
		return c;
	}

	private byte[] recieveResponse(HttpURLConnection connection) throws IOException {
		if (connection.getResponseCode() != HttpURLConnection.HTTP_OK) {
			throw new IOException("Received HTTP error: " + connection.getResponseCode() + " - " + connection.getResponseMessage());
		}

		int length = connection.getContentLength();
		byte[] data = new byte[length];
		InputStream is = connection.getInputStream();
		try {
			int offset = 0;
			while (offset < length) {
				offset += is.read(data, offset, length - offset);
			}
			return data;
		} finally {
			is.close();
		}
	}
}