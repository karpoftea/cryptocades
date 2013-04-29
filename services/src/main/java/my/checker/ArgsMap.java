package my.checker;

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;
import java.util.regex.Pattern;

public class ArgsMap extends HashMap<String, String> {

	private static final Logger log = Logger.getLogger(ArgsMap.class.getName());

	private final Map<String, Pattern> patterns;

	public ArgsMap(String[] args, Map<String, Pattern> patterns) {
		this.patterns = patterns;
		parseArgs(args);
	}

	@Override
	public String put(String key, String value) {
		if (!isValid(key, value)) {
			log.warning("Key:" + key + " value:" + value + " was skipped and not added to args list");
			return null;
		}
		return super.put(key, value);
	}

	boolean isValid(String key, String value) {
		return patterns.containsKey(key) ?
				patterns.get(key).matcher(value).matches() :
				false;
	}

	void parseArgs(String[] cmdArgs) {
		for(int i = 0; i < cmdArgs.length;) {
			if (patterns.containsKey(cmdArgs[i])) {
				if ((i + 1) < cmdArgs.length && !patterns.containsKey(cmdArgs[i + 1])) {
					put(cmdArgs[i], cmdArgs[i + 1]);
					i += 2;
				} else {
					put(cmdArgs[i], "");
					i += 1;
				}
			}
		}
	}
}