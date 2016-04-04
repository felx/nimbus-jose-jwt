package com.nimbusds.jose.proc;


/**
 * Bad JSON Object Signing and Encryption (JOSE) exception.
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-06-10
 */
public class BadJOSEException extends Exception {


	/**
	 * Creates a new bad JOSE exception.
	 *
	 * @param message The exception message.
	 */
	public BadJOSEException(final String message) {

		super(message);
	}


	/**
	 * Creates a new bad JOSE exception.
	 *
	 * @param message The exception message.
	 * @param cause   The exception cause.
	 */
	public BadJOSEException(final String message, final Throwable cause) {

		super(message, cause);
	}
}
