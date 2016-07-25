package com.nimbusds.jose;


/**
 * Key source exception.
 *
 * @author Vladimir Dzhuvinov
 * @version 2016-06-21
 */
public class KeySourceException extends JOSEException {
	

	/**
	 * Creates a new key source exception.
	 *
	 * @param message The message.
	 */
	public KeySourceException(final String message) {
		super(message);
	}


	/**
	 * Creates a new key source exception.
	 *
	 * @param message The message.
	 * @param cause   The cause.
	 */
	public KeySourceException(final String message, final Throwable cause) {
		super(message, cause);
	}
}

