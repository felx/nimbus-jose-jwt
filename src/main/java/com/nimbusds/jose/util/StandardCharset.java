package com.nimbusds.jose.util;


import java.nio.charset.Charset;


/**
 * UTF-8 is the standard charset in JOSE. Works around missing
 * {@link java.nio.charset.StandardCharsets} in Android below API level 19.
 */
public final class StandardCharset {
	
	
	/**
	 * UTF-8
	 */
	public static final Charset UTF_8 = Charset.forName("UTF-8");
	
	
	/**
	 * Prevents public instantiation.
	 */
	private StandardCharset() {}
}
