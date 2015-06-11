package com.nimbusds.jose.proc;


/**
 * Bad JSON Web Encryption (JWE) exception. Used to indicate a JWE-protected
 * object that couldn't be successfully decrypted or its integrity has been
 * compromised.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-06-11)
 */
public class BadJWEException extends BadJOSEException {


	/**
	 * Creates a new bad JWE exception.
	 *
	 * @param message The exception message.
	 */
	public BadJWEException(final String message) {

		super(message);
	}


	/**
	 * Creates a new bad JWE exception.
	 *
	 * @param message The exception message.
	 * @param cause   The exception cause.
	 */
	public BadJWEException(final String message, final Throwable cause) {

		super(message, cause);
	}
}
