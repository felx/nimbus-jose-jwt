package com.nimbusds.jose.jca;


import java.security.Provider;
import java.security.SecureRandom;

import net.jcip.annotations.Immutable;


/**
 * Java Cryptography Architecture (JCA) context intended specifically for
 * JSON Web Encryption (JWE) providers. Allows setting of more specific JCA
 * providers for key encryption, content encryption and MAC computation.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-06-02)
 */
@Immutable
public final class JWEJCAContext extends JCAContext {


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
	 * Creates a new default JCA context for JWE.
	 */
	public JWEJCAContext() {

		this(null, null, null, null, null);
	}


	/**
	 * Creates a new JCA context for JWE.
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
	 *                        requiring a random number, {@code null} to
	 *                        use the default system one.
	 */
	public JWEJCAContext(final Provider generalProvider,
			     final Provider keProvider,
			     final Provider ceProvider,
			     final Provider macProvider,
			     final SecureRandom randomGen) {

		super(generalProvider, randomGen);
		this.keProvider = keProvider;
		this.ceProvider = ceProvider;
		this.macProvider = macProvider;
	}


	/**
	 * Sets the general JCA provider to be used for all operations.
	 *
	 * @param provider The JCA provider to be used for all operations where
	 *                 a more specific one is absent, {@code null} to use
	 *                 the default system provider.
	 *
	 * @return The updated JCA context.
	 */
	public JWEJCAContext withProvider(final Provider provider) {

		return new JWEJCAContext(provider, keProvider, ceProvider, macProvider, getSecureRandom());
	}


	/**
	 * Sets a specific JCA provider for the key encryption.
	 *
	 * @param keProvider The specific JCA provider to be used for the key
	 *                   encryption, {@code null} to fall back to the
	 *                   general one, and if that is not specified to the
	 *                   default system provider.
	 *
	 * @return The updated JCA context.
	 */
	public JWEJCAContext withKeyEncryptionProvider(final Provider keProvider) {

		return new JWEJCAContext(getProvider(), keProvider, ceProvider, macProvider, getSecureRandom());
	}


	/**
	 * Gets the specific JCA provider for the key encryption.
	 *
	 * @return The applicable JCA provider, {@code null} implies the
	 *         default system provider.
	 */
	public Provider getKeyEncryptionProvider() {

		return keProvider != null ? keProvider : getProvider();
	}


	/**
	 * Sets a specific JCA provider for the content encryption.
	 *
	 * @param ceProvider The specific JCA provider to be used for the
	 *                   content encryption, {@code null} to fall back to
	 *                   the general one, and if that is not specified to
	 *                   the default system provider.
	 *
	 * @return The updated JCA context.
	 */
	public JWEJCAContext withContentEncryptionProvider(final Provider ceProvider) {

		return new JWEJCAContext(getProvider(), keProvider, ceProvider, macProvider, getSecureRandom());
	}


	/**
	 * Gets the specific JCA provider for the content encryption.
	 *
	 * @return The applicable JCA provider, {@code null} implies the
	 *         default system provider.
	 */
	public Provider getContentEncryptionProvider() {

		return ceProvider != null ? ceProvider : getProvider();
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
	 * @return The updated JCA context.
	 */
	public JWEJCAContext withMACProvider(final Provider macProvider) {

		return new JWEJCAContext(getProvider(), keProvider, ceProvider, macProvider, getSecureRandom());
	}


	/**
	 * Gets the specific JCA provider for the MAC computation (where
	 * required by the JWE encryption method).
	 *
	 * @return The applicable JCA provider, {@code null} implies the
	 *         default system provider.
	 */
	public Provider getMACProvider() {

		return macProvider != null ? macProvider : getProvider();
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
	public JWEJCAContext withSecureRandom(final SecureRandom randomGen) {

		return new JWEJCAContext(getProvider(), keProvider, ceProvider, macProvider, randomGen);
	}
}
