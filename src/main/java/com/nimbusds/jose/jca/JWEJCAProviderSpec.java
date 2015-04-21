package com.nimbusds.jose.jca;


import java.security.Provider;
import java.security.SecureRandom;

import net.jcip.annotations.Immutable;


/**
 * JCA provider specification for JSON Web Encryption (JWE) operations.
 *
 * @author  Vladimir Dzhuvinov
 * @version $version$ (2015-04-20)
 */
@Immutable
public final class JWEJCAProviderSpec {


	/**
	 * The JCA provider for all operations.
	 */
	private final Provider provider;


	/**
	 * The key encryption provider.
	 */
	private final Provider keProvider;


	/**
	 * The content encryption provider.
	 */
	private final Provider ceProvider;


	/**
	 * The MAC provider.
	 */
	private final Provider macProvider;


	/**
	 * The secure random generator.
	 */
	private final SecureRandom randomGen;


	/**
	 * Creates a new JCA provider specification for JWE.
	 *
	 * @param provider    The specific JCA provider to be used for all
	 *                    operations, {@code null} to use the default one.
	 * @param keProvider  The specific JCA provider to be used for the key
	 *                    encryption, {@code null} to use the default one.
	 * @param ceProvider  The specific JCA provider to be used for the
	 *                    content encryption, {@code null} to use the
	 *                    default one.
	 * @param macProvider The specific JCA provider to be used for the MAC
	 *                    computation (where required by the JWE encryption
	 *                    method), {@code null} to use the default one.
	 * @param randomGen   The specific secure random generator for the
	 *                    initialisation vector and other purposes
	 *                    requiring a random number, {@code null} to use
	 *                    the default one.
	 */
	public JWEJCAProviderSpec(final Provider provider,
				  final Provider keProvider,
				  final Provider ceProvider,
				  final Provider macProvider,
				  final SecureRandom randomGen) {
		this.provider = provider;
		this.keProvider = keProvider;
		this.ceProvider = ceProvider;
		this.macProvider = macProvider;
		this.randomGen = randomGen;
	}


	/**
	 * Creates a new default JCA provider specification for JWE.
	 */
	public JWEJCAProviderSpec() {

		this(null, null, null, null, null);
	}


	/**
	 * Sets the specific JCA provider to be used for all operations.
	 *
	 * @param provider The specific JCA provider to be used for all
	 *                 operations, {@code null} to use the default one.
	 *
	 * @return The updated JCA provider specification.
	 */
	public JWEJCAProviderSpec withProvider(final Provider provider) {

		return new JWEJCAProviderSpec(getProvider(), keProvider, ceProvider, macProvider, randomGen);
	}


	/**
	 * Gets the specific JCA provider to be used for all operations.
	 *
	 * @return The JCA provider, {@code null} implies the default one.
	 */
	public Provider getProvider() {

		return provider;
	}


	/**
	 * Sets a specific JCA provider for the key encryption.
	 *
	 * @param keProvider The JCA provider, {@code null} to use the default
	 *                   one.
	 *
	 * @return The updated JCA provider specification.
	 */
	public JWEJCAProviderSpec withKeyEncryptionProvider(final Provider keProvider) {

		return new JWEJCAProviderSpec(getProvider(), keProvider, ceProvider, macProvider, randomGen);
	}


	/**
	 * Gets the specific JCA provider for the key encryption.
	 *
	 * @return The JCA provider, {@code null} implies the default one.
	 */
	public Provider getKeyEncryptionProvider() {

		return keProvider;
	}


	/**
	 * Sets a specific JCA provider for the content encryption.
	 *
	 * @param ceProvider The JCA provider, {@code null} to use the default
	 *                   one.
	 *
	 * @return The updated JCA provider specification.
	 */
	public JWEJCAProviderSpec withContentEncryptionProvider(final Provider ceProvider) {

		return new JWEJCAProviderSpec(getProvider(), keProvider, ceProvider, macProvider, randomGen);
	}


	/**
	 * Gets the specific JCA provider for the content encryption.
	 *
	 * @return The JCA provider, {@code null} implies the default one.
	 */
	public Provider getContentEncryptionProvider() {

		return ceProvider;
	}


	/**
	 * Sets a specific JCA provider for the MAC computation (where required
	 * by the JWE encryption method).
	 *
	 * @param macProvider The JCA provider, {@code null} to use the
	 *                    default one.
	 *
	 * @return The updated JCA provider specification.
	 */
	public JWEJCAProviderSpec withMACProvider(final Provider macProvider) {

		return new JWEJCAProviderSpec(getProvider(), keProvider, ceProvider, macProvider, randomGen);
	}


	/**
	 * Gets the specific JCA provider for the MAC computation (where
	 * required by the JWE encryption method).
	 *
	 * @return The JCA provider, {@code null} implies the default one.
	 */
	public Provider getMACProvider() {

		return macProvider;
	}


	/**
	 * Sets a specific secure random generator for the initialisation
	 * vector and other purposes requiring a random number.
	 *
	 * @param randomGen The secure random generator, {@code null} to use
	 *                  the default one.
	 *
	 * @return The updated JCA provider specification.
	 */
	public JWEJCAProviderSpec withSecureRandom(final SecureRandom randomGen) {

		return new JWEJCAProviderSpec(getProvider(), keProvider, ceProvider, macProvider, randomGen);
	}


	/**
	 * Gets the specific secure random generator for the initialisation
	 * vector and other purposes requiring a random number.
	 *
	 * @return The secure random generator, {@code null} implies the
	 *         default one.
	 */
	public SecureRandom getSecureRandom() {

		return randomGen;
	}
}
