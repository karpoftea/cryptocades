package my;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class FileUtil {

	public static final int BUFFER_SIZE = 4096;

	/**
	 * Вычитывает данные из InputStream и возвращает их в виде массива байт. Подходит как для файлов, так и для ресурсов.
	 *
	 * @param is - InputStream
	 * @return
	 * @throws java.io.IOException
	 */
	public static byte[] streamToByteArr(InputStream is) throws IOException {
		ByteArrayOutputStream baos = null;

		try {
			baos = new ByteArrayOutputStream();

			byte[] buff = new byte[BUFFER_SIZE];
			int length;
			while (true) {
				length = is.read(buff);
				if (length <= 0) {
					break;
				}
				baos.write(buff, 0, length);
			}

			return baos.toByteArray();
		} catch (IOException e) {
			throw new IOException(e.getMessage());
		} finally {
			try {
				if (is != null) {
					is.close();
				}
				if (baos != null) {
					baos.close();
				}
			} catch (Exception e) {}
		}
	}

	public static String classPath(Class<?> cls) {
		String path = cls.getPackage().getName().replace('.', '/');
		if (!"".equals(path)) {
			path += '/';
		}
		return path;
	}

	/**
	 * Returns resource accessible by {@code loader} located by {@code name}.
	 *
	 * @param loader - class loader for resource loading
	 * @param name   - location of resource
	 * @return resource bytes, or {@code null} on any errors.
	 */
	public static byte[] resourceBytes(ClassLoader loader, String name) {
		try {
			return streamToByteArr(loader.getResourceAsStream(name));
		} catch (Exception e) {
			return null;
		}
	}

	/**
	 * Returns resource accessible by class loader {@code cls.getClassLoader()} located by {@code name}.
	 *
	 * @param cls  - class provides the ClassLoader for resource loading and own package as resource path.
	 * @param name - name of resource in the package of {@code cls}
	 * @return resource bytes, or {@code null} on any errors.
	 */
	public static byte[] resourceBytes(Class<?> cls, String name) {
		return resourceBytes(cls.getClassLoader(), classPath(cls) + name);
	}

	public static <T> X509Certificate readCertificate(Class<T> clazz, String name) {
		try {
			return (X509Certificate) CertificateFactory.getInstance("X509")
													   .generateCertificate(new ByteArrayInputStream(resourceBytes(clazz, name)));
		} catch (CertificateException e) {
			throw new RuntimeException(e);
		}
	}

	public static void writeToFile(byte[] data, String path) throws FileNotFoundException {
		final FileOutputStream os = new FileOutputStream(path);
		try {
			os.write(data);
			os.flush();
		} catch (Exception e) {
			throw new RuntimeException(e);
		} finally {
			try {
				os.close();
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		}
	}

	public static byte[] readFile (String file) throws IOException {
		return readFile(new File(file));
	}

	public static byte[] readFile (File file) throws IOException {
		// Open file
		RandomAccessFile f = new RandomAccessFile(file, "r");

		try {
			// Get and check length
			long longlength = f.length();
			int length = (int) longlength;
			if (length != longlength) throw new IOException("File size >= 2 GB");

			// Read file and return data
			byte[] data = new byte[length];
			f.readFully(data);
			return data;
		}
		finally {
			f.close();
		}
	}
}