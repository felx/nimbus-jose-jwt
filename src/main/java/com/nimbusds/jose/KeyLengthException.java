package com.nimbusds.jose;


/**
 * Key length exception.
 *
 * @author Vladimir Dzhuvinov
 * @version 205-06-29
 */
public class KeyLengthException extends KeyException {


	/**
	 * The expected key length.
	 */
	private final int expectedLength;


	/**
	 * The algorithm.
	 */
	private final Algorithm alg;


	/**
	 * Creates a new key length exception.
	 *
	 * @param message The exception message.
	 */
	public KeyLengthException(final String message) {

		super(message);
		expectedLength = 0;
		alg = null;
	}


	/**
	 * Creates a new key length exception.
	 *
	 * @param alg The JOSE algorithm, {@code null} if not specified.
	 */
	public KeyLengthException(final Algorithm alg) {

		this(0, alg);
	}


	/**
	 * Creates a new key length exception.
	 *
	 * @param expectedLength The expected key length in bits, zero if not
	 *                       specified.
	 * @param alg            The JOSE algorithm, {@code null} if not
	 *                       specified.
	 */
	public KeyLengthException(final int expectedLength, final Algorithm alg) {

		super((
			(expectedLength > 0) ? "The expected key length is " + expectedLength + " bits" : "Unexpected key length") +
			((alg != null) ? " (for " + alg + " algorithm)" : "")
		);

		this.expectedLength = expectedLength;
		this.alg = alg;
	}


	/**
	 * Returns the expected key length.
	 *
	 * @return The expected key length in bits, zero if not specified.
	 */
	public int getExpectedKeyLength() {

		return expectedLength;
	}


	/**
	 * Returns the algorithm.
	 *
	 * @return The JOSE algorithm, {@code null} if not specified.
	 */
	public Algorithm getAlgorithm() {

		return alg;
	}
}
