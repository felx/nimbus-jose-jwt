package com.nimbusds.jose;


import java.security.Key;


/**
 * Key type exception.
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-06-29
 */
public class KeyTypeException extends KeyException {


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
