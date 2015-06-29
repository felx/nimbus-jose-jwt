package com.nimbusds.jose.proc;


/**
 * Base abstract processor of received {@link com.nimbusds.jose.JOSEObject}s.
 * Provides getters and setters for JWS / JWE key selectors and JWS verifier /
 * JWE decrypter factories.
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-06-30
 */
public abstract class BaseJOSEProcessor<C extends SecurityContext> {


	/**
	 * The JWS key selector.
	 */
	private JWSKeySelector<C> jwsKeySelector;


	/**
	 * The JWE key selector.
	 */
	private JWEKeySelector<C> jweKeySelector;


	/**
	 * The JWS verifier factory.
	 */
	private JWSVerifierFactory jwsVerifierFactory = new DefaultJWSVerifierFactory();


	/**
	 * The JWE decrypter factory.
	 */
	private JWEDecrypterFactory jweDecrypterFactory = new DefaultJWEDecrypterFactory();



	/**
	 * Gets the JWS key selector.
	 *
	 * @return The JWS key selector, {@code null} if not specified.
	 */
	public JWSKeySelector<C> getJWSKeySelector() {

		return jwsKeySelector;
	}


	/**
	 * Sets the JWS key selector.
	 *
	 * @param jwsKeySelector The JWS key selector, {@code null} if not
	 *                       specified.
	 */
	public void setJWSKeySelector(final JWSKeySelector<C> jwsKeySelector) {

		this.jwsKeySelector = jwsKeySelector;
	}


	/**
	 * Gets the JWE key selector.
	 *
	 * @return The JWE key selector, {@code null} if not specified.
	 */
	public JWEKeySelector<C> getJWEKeySelector() {

		return jweKeySelector;
	}


	/**
	 * Sets the JWE key selector.
	 *
	 * @param jweKeySelector The JWE key selector, {@code null} if not
	 *                       specified.
	 */
	public void setJWEKeySelector(final JWEKeySelector<C> jweKeySelector) {

		this.jweKeySelector = jweKeySelector;
	}


	/**
	 * Gets the factory for creating JWS verifier instances.
	 *
	 * @return The JWS verifier factory, {@code null} if not specified.
	 */
	public JWSVerifierFactory getJWSVerifierFactory() {

		return jwsVerifierFactory;
	}


	/**
	 * Sets the factory for creating JWS verifier instances.
	 *
	 * @param factory The JWS verifier factory, {@code null} if not
	 *                specified.
	 */
	public void setJWSVerifierFactory(final JWSVerifierFactory factory) {

		jwsVerifierFactory = factory;
	}


	/**
	 * Gets the factory for creating JWE decrypter instances.
	 *
	 * @return The JWE decrypter factory, {@code null} if not specified.
	 */
	public JWEDecrypterFactory getJWEDecrypterFactory() {

		return jweDecrypterFactory;
	}


	/**
	 * Sets the factory for creating JWE decrypter instances.
	 *
	 * @param factory The JWE decrypter factory, {@code null} if not
	 *                specified.
	 */
	public void setJWEDecrypterFactory(final JWEDecrypterFactory factory) {

		jweDecrypterFactory = factory;
	}
}
