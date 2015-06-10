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
 * @version $version$ (2015-06-10)
 */
@ThreadSafe
public class DefaultJOSEProcessor<C extends SecurityContext>
	implements JOSEProcessor<Payload, C>, JWSKeySelectorAware<C>, JWEKeySelectorAware<C> {


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



	@Override
	public JWSKeySelector<C> getJWSKeySelector() {

		return jwsKeySelector;
	}


	@Override
	public void setJWSKeySelector(final JWSKeySelector jwsKeySelector) {

		this.jwsKeySelector = jwsKeySelector;
	}


	@Override
	public JWEKeySelector<C> getJWEKeySelector() {

		return jweKeySelector;
	}


	@Override
	public void setJWEKeySelector(final JWEKeySelector jweKeySelector) {

		this.jweKeySelector = jweKeySelector;
	}


	public JWSVerifierFactory getJWSVerifierFactory() {

		return jwsVerifierFactory;
	}


	public void setJWSVerifierFactory(final JWSVerifierFactory factory) {

		jwsVerifierFactory = factory;
	}


	public JWEDecrypterFactory getJWEDecrypterFactory() {

		return jweDecrypterFactory;
	}


	public void setJWEDecrypterFactory(final JWEDecrypterFactory factory) {

		jweDecrypterFactory = factory;
	}


	public Payload process(final String compactJOSE, final C context)
		throws ParseException, JOSEException {

		return null;
	}


	@Override
	public Payload process(final PlainObject plainObject, C context)
		throws BadJOSEException {

		throw new BadJOSEException();
	}


	@Override
	public Payload process(final JWSObject jwsObject, C context) {

		if (jwsKeySelector == null || jwsVerifierFactory == null) {
			return null;
		}

		List<? extends Key> keyCandidates = jwsKeySelector.selectJWSKeys(jwsObject.getHeader(), context);

		if (keyCandidates == null || keyCandidates.isEmpty()) {
			return null;
		}

		for (Key key: keyCandidates) {

			JWSVerifier verifier;

			try {
				verifier = jwsVerifierFactory.createJWSVerifier(jwsObject.getHeader(), key);

			} catch (JOSEException e) {
				return null;
			}

			if (verifier == null) {
				continue;
			}

			final boolean validSignature;

			try {
				validSignature = jwsObject.verify(verifier);
			} catch (JOSEException e) {

				return null;
			}

			if (validSignature) {
				return jwsObject.getPayload();
			}

			// Invalid signature
			return null;
		}

		return null;
	}


	@Override
	public Payload process(final JWEObject jweObject, C context) {

		if (jweKeySelector == null || jweDecrypterFactory == null) {
			return null;
		}

		List<? extends Key> keyCandidates = jweKeySelector.selectJWEKeys(jweObject.getHeader(), context);

		if (keyCandidates == null || keyCandidates.isEmpty()) {
			return null;
		}

		return null;
	}
}
