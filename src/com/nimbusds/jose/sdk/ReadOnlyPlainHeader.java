package com.nimbusds.jose.sdk;


/**
 * Read-only view of a {@link PlainHeader plain header}.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-09-19)
 */
public interface ReadOnlyPlainHeader extends ReadOnlyHeader {
	
	
	/**
	 * Gets the algorithm ({@code alg}) parameter.
	 *
	 * @return {@link Algorithm#NONE}.
	 */
	public Algorithm getAlgorithm();
}
