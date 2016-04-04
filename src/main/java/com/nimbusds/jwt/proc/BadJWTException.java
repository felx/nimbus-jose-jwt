package com.nimbusds.jwt.proc;


import com.nimbusds.jose.proc.BadJOSEException;


/**
 * Bad JSON Web Token (JWT) exception.
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-06-29
 */
public class BadJWTException extends BadJOSEException {


	/**
	 * Creates a new bad JWT exception.
	 *
	 * @param message The exception message.
	 */
	public BadJWTException(final String message) {

		super(message);
	}


	/**
	 * Creates a new bad JWT exception.
	 *
	 * @param message The exception message.
	 * @param cause   The exception cause.
	 */
	public BadJWTException(final String message, final Throwable cause) {

		super(message, cause);
	}
}
