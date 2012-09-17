package com.nimbusds.jose;


/**
 * Parse exception.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-09-17)
 */
public class ParseException extends Exception {


	/**
	 * Creates a new parse exception with the specified message.
	 *
	 * @param message The exception message.
	 */
	public ParseException(final String message) {
		
		super(message);
	}
	
	
	/**
	 * Creates a new parse exception with the specified message and cause.
	 *
	 * @param message The exception message.
	 * @param cause   The exception cause.
	 */
	public ParseException(final String message, final Throwable cause) {
		
		super(message, cause);
	}
}
