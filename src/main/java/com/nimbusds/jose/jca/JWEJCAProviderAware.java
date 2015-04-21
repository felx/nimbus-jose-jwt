package com.nimbusds.jose.jca;


/**
 * Interface for setting one or more Java Cryptography Architecture (JCA)
 * {@link java.security.Provider providers} for JSON Web Encryption (JWE)
 * operations.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-04-21)
 */
public interface JWEJCAProviderAware {


	/**
	 * Sets a JCA provider specification for JWE operations.
	 *
	 * @param jcaProviderSpec The JCA provider specification, must not be
	 *                        {@code null}.
	 */
	void setJWEJCAProvider(final JWEJCAProviderSpec jcaProviderSpec);


	/**
	 * Returns the JCA provider specification for JWE operations.
	 *
	 * @return The JCA provider specification.
	 */
	JWEJCAProviderSpec getJWEJCAProvider();
}
