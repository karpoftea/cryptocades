package my.checker;

import org.testng.Assert;
import org.testng.annotations.Test;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

public class ArgsMapUnitTest {

	@Test
	public void testConstructor_1() {
		String certFileName = "certfile.cer";
		ArgsMap map = new ArgsMap(new String[] {"-all", "-cert", certFileName}, jvmCheckerAppPatterns);

		assertEquals(map.size(), 2);
		assertTrue(map.containsKey("-all"));
		assertTrue(map.containsKey("-cert"));
		assertEquals(map.get("-cert"), certFileName);
	}

	@Test
	public void testConstructor_2() {
		String certFileName = "certfile.cer";
		ArgsMap map = new ArgsMap(new String[] {"-cert", certFileName, "-all", }, jvmCheckerAppPatterns);

		assertEquals(map.size(), 2);
		assertTrue(map.containsKey("-all"));
		assertTrue(map.containsKey("-cert"));
		assertEquals(map.get("-cert"), certFileName);
	}

	static final Map<String, Pattern> jvmCheckerAppPatterns = new HashMap<String, Pattern>();
	static {
		jvmCheckerAppPatterns.put("-all", Pattern.compile("^$"));
		jvmCheckerAppPatterns.put("-cert", Pattern.compile(".*"));
	}
}
