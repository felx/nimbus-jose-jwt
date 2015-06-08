package com.nimbusds.jose.handler;


import java.security.Key;
import java.text.ParseException;
import java.util.List;

import com.nimbusds.jose.*;
import net.jcip.annotations.ThreadSafe;


/**
 * Created by vd on 15-6-8.
 */
@ThreadSafe
public class JOSEHandler <C extends Context> implements JOSEObjectHandler<Payload, C> {


	private JWSKeySelector<C> jwsKeySelector;


	private JWEKeySelector<C> jweKeySelector;


	private JWSVerifierFactory jwsVerifierFactory;


	private JWEDecrypterFactory jweDecrypterFactory;



	public JWSKeySelector<C> getJWSKeySelector() {

		return jwsKeySelector;
	}


	public void setJWSKeySelector(final JWSKeySelector jwsKeySelector) {

		this.jwsKeySelector = jwsKeySelector;
	}


	public JWEKeySelector<C> getJWEKeySelector() {

		return jweKeySelector;
	}


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


	public Payload handle(final String compactJOSE, final C context)
		throws ParseException, JOSEException {

		return JOSEObject.parse(compactJOSE, this, context);
	}


	@Override
	public Payload onPlainObject(final PlainObject plainObject, C context) {

		return null;
	}


	@Override
	public Payload onJWSObject(final JWSObject jwsObject, C context) {

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
		}

		return null;
	}


	@Override
	public Payload onJWEObject(final JWEObject jweObject, C context) {

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
