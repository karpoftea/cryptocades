package my.transport;

/** @author i.karpov */
public class HttpClientFacade {

	public static HttpClient createClient(RequestParameters params) {
		return new SimpleHttpClient(params);
	}
}