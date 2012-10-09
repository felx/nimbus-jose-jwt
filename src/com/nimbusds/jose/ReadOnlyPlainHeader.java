package com.nimbusds.jose;


/**
 * Read-only view of a {@link PlainHeader plaintext JOSE header}.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-09-28)
 */
public interface ReadOnlyPlainHeader extends ReadOnlyHeader {
	
	
	/**
	 * Gets the algorithm ({@code alg}) parameter.
	 *
	 * @return {@link Algorithm#NONE}.
	 */
	@Override
	public Algorithm getAlgorithm();
}
