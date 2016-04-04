package com.nimbusds.jose;


/**
 * Javascript Object Signing and Encryption (JOSE) exception.
 *
 * @author Vladimir Dzhuvinov
 * @version 2012-09-15
 */
public class JOSEException extends Exception {


	private static final long serialVersionUID = 1L;


	/**
	 * Creates a new JOSE exception with the specified message.
	 *
	 * @param message The exception message.
	 */
	public JOSEException(final String message) {

		super(message);
	}


	/**
	 * Creates a new JOSE exception with the specified message and cause.
	 *
	 * @param message The exception message.
	 * @param cause   The exception cause.
	 */
	public JOSEException(final String message, final Throwable cause) {

		super(message, cause);
	}
}
