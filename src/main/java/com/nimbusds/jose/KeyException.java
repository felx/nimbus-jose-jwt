package com.nimbusds.jose;


/**
 * Key exception.
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-06-29
 */
public class KeyException extends JOSEException {


	/**
	 * Creates a new key exception with the specified message.
	 *
	 * @param message The exception message.
	 */
	public KeyException(final String message) {

		super(message);
	}
}
