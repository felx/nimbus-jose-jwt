package com.nimbusds.jose.sdk;


/**
 * Javascript Object Signing and Encryption (JOSE) exception.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-09-15)
 */
public class JOSEException extends Exception {


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
