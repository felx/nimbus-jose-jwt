package com.nimbusds.jose.proc;


/**
 * JSON Web Encryption (JWE) key selector aware interface.
 * 
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-06-10)
 */
public interface JWEKeySelectorAware<C extends SecurityContext> {


	/**
	 * Gets the JWE key selector.
	 *
	 * @return The JWE key selector, {@code null} if not specified.
	 */
	JWEKeySelector<C> getJWEKeySelector();


	/**
	 * Sets the JWE key selector.
	 *
	 * @param JWEKeySelector The JWE key selector, {@code null} if not
	 *                       specified.       
	 */
	void setJWEKeySelector(final JWEKeySelector<C> JWEKeySelector);
}
