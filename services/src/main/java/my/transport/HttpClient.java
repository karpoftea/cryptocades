package my.transport;

import java.io.IOException;

/** @author i.karpov */
public interface HttpClient {

	byte[] call() throws IOException;
}