package com.nimbusds.jose.proc;


import java.security.Key;

import com.nimbusds.jose.JOSEException;


/**
 * Key type exception.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-06-08)
 */
public class KeyTypeException extends JOSEException {


	/**
	 * Creates a new key type exception.
	 *
	 * @param expectedKeyClass The expected key class. Should not be
	 *                         {@code null}.
	 */
	public KeyTypeException(final Class<? extends Key> expectedKeyClass) {

		super("Invalid key: Must be an instance of " + expectedKeyClass);
	}
}
