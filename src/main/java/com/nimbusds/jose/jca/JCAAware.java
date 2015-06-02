package com.nimbusds.jose.jca;


/**
 * Interface for a Java Cryptography Architecture (JCA) aware object, intended
 * for setting a JCA {@link java.security.Provider provider} and
 * {@link java.security.SecureRandom secure random generator}.
 */
public interface JCAAware<T extends JCAContext> {


	/**
	 * Sets the JCA context.
	 *
	 * @param context The JCA context. Must not be {@code null}.
	 */
	void setJCAContext(T context);


	/**
	 * Gets the JCA context.
	 *
	 * @return The JCA context. Must not be {@code null}.
	 */
	T getJCAContext();
}
