package com.nimbusds.jose.jca;


import java.security.Provider;
import java.security.SecureRandom;

import net.jcip.annotations.Immutable;


/**
 * JCA provider specification for JSON Web Encryption (JWE) operations.
 *
 * @author  Vladimir Dzhuvinov
 * @version $version$ (2015-05-16)
 */
@Immutable
public final class JWEJCAProviderSpec {


	/**
	 * The general JCA provider for all operations where a more specific
	 * one is absent.
	 */
	private final Provider generalProvider;


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
	 * @param generalProvider The general JCA provider to be used for all
	 *                        operations where a more specific one is
	 *                        absent, {@code null} to use the default
	 *                        system provider.
	 * @param keProvider      The specific JCA provider to be used for the
	 *                        key encryption, {@code null} to fall back to
	 *                        the general one, and if that is not specified
	 *                        to the default system provider.
	 * @param ceProvider      The specific JCA provider to be used for the
	 *                        content encryption, {@code null} to fall back
	 *                        to the general one, and if that is not
	 *                        specified to the default system provider.
	 * @param macProvider     The specific JCA provider to be used for the
	 *                        MAC computation (where required by the JWE
	 *                        encryption method), {@code null} to fall back
	 *                        to the general one, and if that is not
	 *                        specified to the default system provider.
	 * @param randomGen       The specific secure random generator for the
	 *                        initialisation vector and other purposes
	 *                        requiring a random number, {@code null} to use
	 *                        the default one.
	 */
	public JWEJCAProviderSpec(final Provider generalProvider,
				  final Provider keProvider,
				  final Provider ceProvider,
				  final Provider macProvider,
				  final SecureRandom randomGen) {

		this.generalProvider = generalProvider;
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
	 * @param provider The general JCA provider to be used for all
	 *                 operations where a more specific one is absent,
	 *                 {@code null} to use the default system provider.
	 *
	 * @return The updated JCA provider specification.
	 */
	public JWEJCAProviderSpec withGeneralProvider(final Provider provider) {

		return new JWEJCAProviderSpec(provider, keProvider, ceProvider, macProvider, randomGen);
	}


	/**
	 * Gets the general JCA provider to be used for all operations.
	 *
	 * @return The JCA provider, {@code null} implies the default system
	 *         provider.
	 */
	public Provider getGeneralProvider() {

		return generalProvider;
	}


	/**
	 * Sets a specific JCA provider for the key encryption.
	 *
	 * @param keProvider The specific JCA provider to be used for the key
	 *                   encryption, {@code null} to fall back to the
	 *                   general one, and if that is not specified to the
	 *                   default system provider.
	 *
	 * @return The updated JCA provider specification.
	 */
	public JWEJCAProviderSpec withKeyEncryptionProvider(final Provider keProvider) {

		return new JWEJCAProviderSpec(getGeneralProvider(), keProvider, ceProvider, macProvider, randomGen);
	}


	/**
	 * Gets the specific JCA provider for the key encryption.
	 *
	 * @return The applicable JCA provider, {@code null} implies the
	 *         default system provider.
	 */
	public Provider getKeyEncryptionProvider() {

		return keProvider != null ? keProvider : generalProvider;
	}


	/**
	 * Sets a specific JCA provider for the content encryption.
	 *
	 * @param ceProvider The specific JCA provider to be used for the
	 *                   content encryption, {@code null} to fall back to
	 *                   the general one, and if that is not specified to
	 *                   the default system provider.
	 *
	 * @return The updated JCA provider specification.
	 */
	public JWEJCAProviderSpec withContentEncryptionProvider(final Provider ceProvider) {

		return new JWEJCAProviderSpec(getGeneralProvider(), keProvider, ceProvider, macProvider, randomGen);
	}


	/**
	 * Gets the specific JCA provider for the content encryption.
	 *
	 * @return The applicable JCA provider, {@code null} implies the
	 *         default system provider.
	 */
	public Provider getContentEncryptionProvider() {

		return ceProvider != null ? ceProvider : generalProvider;
	}


	/**
	 * Sets a specific JCA provider for the MAC computation (where required
	 * by the JWE encryption method).
	 *
	 * @param macProvider The specific JCA provider to be used for the MAC
	 *                    computation (where required by the JWE encryption
	 *                    method), {@code null} to fall back to the general
	 *                    one, and if that is not specified to the default
	 *                    system provider.
	 *
	 * @return The updated JCA provider specification.
	 */
	public JWEJCAProviderSpec withMACProvider(final Provider macProvider) {

		return new JWEJCAProviderSpec(getGeneralProvider(), keProvider, ceProvider, macProvider, randomGen);
	}


	/**
	 * Gets the specific JCA provider for the MAC computation (where
	 * required by the JWE encryption method).
	 *
	 * @return The applicable JCA provider, {@code null} implies the
	 *         default system provider.
	 */
	public Provider getMACProvider() {

		return macProvider != null ? macProvider : generalProvider;
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

		return new JWEJCAProviderSpec(getGeneralProvider(), keProvider, ceProvider, macProvider, randomGen);
	}


	/**
	 * Gets the secure random generator for the initialisation vector and
	 * other purposes requiring a random number.
	 *
	 * @return The specific secure random generator (if specified), else
	 *         the default one.
	 */
	public SecureRandom getSecureRandom() {

		return randomGen != null ? randomGen : new SecureRandom();
	}
}
