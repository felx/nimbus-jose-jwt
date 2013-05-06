package com.nimbusds.jose.util;


import java.io.UnsupportedEncodingException;

import com.nimbusds.jose.JOSEException;


/**
 * String utilities.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-05-06)
 */
public class StringUtils {


	/**
	 * Converts the specified string to a byte array.
	 *
	 * @param s The input string to convert. Must be UTF-8 encoded and not
	 *          {@code null}.
	 *
	 * @return The resulting byte array.
	 *
	 * @throws JOSEException If UTF-8 encoding is not supported.
	 */
	public static byte[] toByteArray(final String s)
		throws JOSEException {

		try {
			return s.getBytes("UTF-8");

		} catch (UnsupportedEncodingException e) {

			throw new JOSEException(e.getMessage(), e);
		}
	}


	/**
	 * Prevents public instantiation.
	 */
	private StringUtils() {

	}
}