package com.nimbusds.jose.proc;


/**
 * JSON Web Signature (JWS) key selector aware interface.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-06-10)
 */
public interface JWSKeySelectorAware<C extends SecurityContext> {


	/**
	 * Gets the JWS key selector.
	 *
	 * @return The JWS key selector, {@code null} if not specified.
	 */
	JWSKeySelector<C> getJWSKeySelector();


	/**
	 * Sets the JWS key selector.
	 *
	 * @param jwsKeySelector The JWS key selector, {@code null} if not
	 *                       specified.
	 */
	void setJWSKeySelector(final JWSKeySelector<C> jwsKeySelector);
}
