package com.nimbusds.jose.crypto;


import java.security.Provider;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.Set;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEAlgorithmProvider;


/**
 * The base abstract class for JSON Web Encryption (JWE) encrypters and 
 * decrypters.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-01-28)
 */
abstract class BaseJWEProvider implements JWEAlgorithmProvider {


	/**
	 * The supported algorithms.
	 */
	private final Set<JWEAlgorithm> algs;


	/**
	 * The supported encryption methods.
	 */
	private final Set<EncryptionMethod> encs;


	/**
	 * The JCA provider for the key encryption, {@code null} if not
	 * specified (implies default one).
	 */
	protected Provider keyEncryptionProvider = null;


	/**
	 * The JCA provider for the content encryption, {@code null} if not
	 * specified (implies default one).
	 */
	protected Provider contentEncryptionProvider = null;


	/**
	 * The JCA provider for the HMAC computation, {@code null} if not
	 * specified (implies default one).
	 */
	protected Provider hmacProvider = null;


	/**
	 * The SecureRandom instance used for encryption/decryption.
	 */
	private SecureRandom randomGen = null;


	/**
	 * Creates a new base JWE provider.
	 *
	 * @param algs The supported JWE algorithms. Must not be {@code null}.
	 * @param encs The supported encryption methods. Must not be 
	 *             {@code null}.
	 */
	public BaseJWEProvider(final Set<JWEAlgorithm> algs,
		               final Set<EncryptionMethod> encs) {

		if (algs == null) {
			throw new IllegalArgumentException("The supported JWE algorithm set must not be null");
		}

		this.algs = Collections.unmodifiableSet(algs);


		if (encs == null) {
			throw new IllegalArgumentException("The supported encryption methods must not be null");
		}

		this.encs = encs;
	}


	@Override
	public Set<JWEAlgorithm> supportedAlgorithms() {

		return algs;
	}


	@Override
	public Set<EncryptionMethod> supportedEncryptionMethods() {

		return encs;
	}


	@Override
	public void setProvider(final Provider provider) {

		setKeyEncryptionProvider(provider);
		setContentEncryptionProvider(provider);
		setHMACProvider(provider);
	}


	@Override
	public void setKeyEncryptionProvider(final Provider provider) {

		keyEncryptionProvider = provider;
	}


	@Override
	public void setContentEncryptionProvider(final Provider provider) {

		contentEncryptionProvider = provider;
	}


	@Override
	public void setHMACProvider(final Provider provider) {

		hmacProvider = provider;
	}


	@Override
	public void setSecureRandom(final SecureRandom randomGen) {

		this.randomGen = randomGen;
	}


	/**
	 * Returns the secure random generator for this JWE provider.
	 *
	 * @return The secure random generator.
	 */
	protected SecureRandom getSecureRandom() {
		if (randomGen == null) {
			// Use default SecureRandom instance for this JVM/platform.
			this.randomGen = new SecureRandom();
			return randomGen;
		} else {
			// Use the specified instance.
			return randomGen;
		}
	}
}

