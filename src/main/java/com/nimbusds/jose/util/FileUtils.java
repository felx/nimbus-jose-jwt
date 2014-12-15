package com.nimbusds.jose.util;


import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;


/**
 * File utilities.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-12-14)
 */
public class FileUtils {


	/**
	 * Reads the specified file.
	 *
	 * @param file The file to read. Must not be {@code null}.
	 *
	 * @return The file content.
	 *
	 * @throws IOException If the file couldn't be read.
	 */
	public static String readFile(final File file)
		throws IOException {

		BufferedReader br = new BufferedReader(new FileReader(file));
		try {
			StringBuilder sb = new StringBuilder();
			String line = br.readLine();

			while (line != null) {
				sb.append(line);
				sb.append(System.lineSeparator());
				line = br.readLine();
			}
			return sb.toString();
		} finally {
			br.close();
		}
	}


	/**
	 * Prevents public instantiation.
	 */
	private FileUtils() { }
}
