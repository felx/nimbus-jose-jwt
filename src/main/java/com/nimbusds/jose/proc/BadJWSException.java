package com.nimbusds.jose.proc;


/**
 * Bad JSON Web Signature (JWS) exception. Used to indicate an invalid
 * signature or hash-based message authentication code (HMAC).
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-06-11
 */
public class BadJWSException extends BadJOSEException {


	/**
	 * Creates a new bad JWS exception.
	 *
	 * @param message The exception message.
	 */
	public BadJWSException(final String message) {

		super(message);
	}


	/**
	 * Creates a new bad JWS exception.
	 *
	 * @param message The exception message.
	 * @param cause   The exception cause.
	 */
	public BadJWSException(final String message, final Throwable cause) {

		super(message, cause);
	}
}
