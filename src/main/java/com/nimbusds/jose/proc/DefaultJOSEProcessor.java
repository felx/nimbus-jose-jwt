package com.nimbusds.jose.proc;


import java.security.Key;
import java.text.ParseException;
import java.util.List;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.*;


/**
 * Default processor of received {@link com.nimbusds.jose.JOSEObject}s.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-06-11)
 */
@ThreadSafe
public class DefaultJOSEProcessor<C extends SecurityContext>
	implements JOSEProcessor<Payload, C> {


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
	private JWSVerifierFactory jwsVerifierFactory;


	/**
	 * The JWE decrypter factory.
	 */
	private JWEDecrypterFactory jweDecrypterFactory;



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


	@Override
	public Payload process(final String compactJOSE, final C context)
		throws ParseException, JOSEException {

		return null;
	}


	@Override
	public Payload process(final PlainObject plainObject, C context)
		throws BadJOSEException {

		throw new BadJOSEException("Unsecured (plain) JOSE objects are rejected");
	}


	@Override
	public Payload process(final JWSObject jwsObject, C context)
		throws BadJOSEException, JOSEException {

		if (jwsKeySelector == null) {
			throw new BadJOSEException("JWS object rejected: No JWS key selector is configured");
		}

		if (jwsVerifierFactory == null) {
			throw new BadJOSEException("JWS object rejected: No JWS verifier is configured");
		}

		List<? extends Key> keyCandidates = jwsKeySelector.selectJWSKeys(jwsObject.getHeader(), context);

		if (keyCandidates == null || keyCandidates.isEmpty()) {
			throw new BadJOSEException("JWS object rejected: No matching key(s) found");
		}

		for (Key key: keyCandidates) {

			JWSVerifier verifier = jwsVerifierFactory.createJWSVerifier(jwsObject.getHeader(), key);

			if (verifier == null) {
				continue;
			}

			final boolean validSignature = jwsObject.verify(verifier);

			if (validSignature) {
				return jwsObject.getPayload();
			}

			// Invalid signature
			throw new BadJWSException("JWS object rejected: Invalid signature");
		}

		throw new BadJOSEException("JWS object rejected: No matching verifier(s) found");
	}


	@Override
	public Payload process(final JWEObject jweObject, C context)
		throws BadJOSEException, JOSEException {

		if (jweKeySelector == null) {
			throw new BadJOSEException("JWE object rejected: No JWE key selector is configured");
		}

		if (jweDecrypterFactory == null) {
			throw new BadJOSEException("JWE object rejected: No JWE decrypter is configured");
		}

		List<? extends Key> keyCandidates = jweKeySelector.selectJWEKeys(jweObject.getHeader(), context);

		if (keyCandidates == null || keyCandidates.isEmpty()) {
			throw new BadJOSEException("JWE object rejected: No matching key(s) found");
		}

		for (Key key: keyCandidates) {

			JWEDecrypter decrypter = jweDecrypterFactory.createJWEDecrypter(jweObject.getHeader(), key);

			if (decrypter == null) {
				continue;
			}

			try {
				jweObject.decrypt(decrypter);

			} catch (JOSEException e) {
				// Decryption failed
				throw new BadJWEException("JWE object rejected: " + e.getMessage(), e);
			}

			// TODO check for nested JWS

			return jweObject.getPayload();
		}

		throw new BadJOSEException("JWE object rejected: No matching decrypter(s) found");
	}
}
