package com.nimbusds.jose;


/**
 * Remote key source exception.
 *
 * @author Vladimir Dzhuvinov
 * @version 2016-06-21
 */
public class RemoteKeySourceException extends KeySourceException {
	

	/**
	 * Creates a new remote key source exception.
	 *
	 * @param message The message.
	 * @param cause   The cause.
	 */
	public RemoteKeySourceException(final String message, final Throwable cause) {
		super(message, cause);
	}
}
