package com.nimbusds.jose.jca;


/**
 * Interface for a Java Cryptography Architecture (JCA) aware object, intended
 * for setting a JCA {@link java.security.Provider provider} and
 * {@link java.security.SecureRandom secure random generator}.
 *
 * @version 2015-06-30
 */
public interface JCAAware<T extends JCAContext> {


	/**
	 * Returns the Java Cryptography Architecture (JCA) context. May be
	 * used to set a specific JCA security provider or secure random
	 * generator.
	 *
	 * @return The JCA context. Not {@code null}.
	 */
	T getJCAContext();
}
