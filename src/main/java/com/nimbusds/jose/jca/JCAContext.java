package com.nimbusds.jose.jca;


import java.security.Provider;
import java.security.SecureRandom;


/**
 * Java Cryptography Architecture (JCA) context, consisting of a JCA
 * {@link java.security.Provider provider} and
 * {@link java.security.SecureRandom secure random generator}.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-06-02)
 */
public class JCAContext {


	/**
	 * The JCA provider.
	 */
	private final Provider provider;


	/**
	 * The secure random generator.
	 */
	private final SecureRandom randomGen;


	/**
	 * Creates a new default JCA context.
	 */
	public JCAContext() {

		this(null, null);
	}


	/**
	 * Creates a new JCA context.
	 *
	 * @param provider  The JCA provider, {@code null} to use the default
	 *                  system one.
	 * @param randomGen The specific secure random generator, {@code null}
	 *                  to use the default system one.
	 */
	public JCAContext(final Provider provider, final SecureRandom randomGen) {

		this.provider = provider;
		this.randomGen = randomGen;
	}


	/**
	 * Gets the JCA provider to be used for all operations.
	 *
	 * @return The JCA provider to be used for all operations where a more
	 *         specific one is absent, {@code null} implies the default
	 *         system provider.
	 */
	public Provider getProvider() {

		return provider;
	}


	/**
	 * Sets the JCA provider to be used for all operations.
	 *
	 * @param provider The JCA provider to be used for all operations where
	 *                 a more specific one is absent, {@code null} to use
	 *                 the default system provider.
	 *
	 * @return The updated JCA context.
	 */
	public JCAContext withProvider(final Provider provider) {

		return new JCAContext(provider, getSecureRandom());
	}


	/**
	 * Gets the secure random generator. Intended for generation of
	 * initialisation vectors and other purposes that require a secure
	 * random generator.
	 *
	 * @return The specific secure random generator (if available), else
	 *         the default system one.
	 */
	public SecureRandom getSecureRandom() {

		return randomGen != null ? randomGen : new SecureRandom();
	}


	/**
	 * Sets a specific secure random generator for the initialisation
	 * vector and other purposes requiring a random number.
	 *
	 * @param randomGen The secure random generator, {@code null} to use
	 *                  the default system one.
	 *
	 * @return The updated JCA context.
	 */
	public JCAContext withSecureRandom(final SecureRandom randomGen) {

		return new JCAContext(provider, randomGen);
	}
}
