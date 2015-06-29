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
 * @version 2015-06-30
 */
@ThreadSafe
public class DefaultJOSEProcessor<C extends SecurityContext>
	extends BaseJOSEProcessor<C>
	implements JOSEProcessor<Payload, C>{

	@Override
	public Payload process(final String compactJOSE, final C context)
		throws ParseException, BadJOSEException, JOSEException {

		JOSEObject joseObject = JOSEObject.parse(compactJOSE);

		if (joseObject instanceof JWSObject) {
			return process((JWSObject)joseObject, context);
		}

		if (joseObject instanceof JWEObject) {
			return process((JWEObject)joseObject, context);
		}

		if (joseObject instanceof PlainObject) {
			return process((PlainObject)joseObject, context);
		}

		// Should never happen
		throw new JOSEException("Unexpected JOSE object type: " + joseObject.getClass());
	}


	@Override
	public Payload process(final PlainObject plainObject, C context)
		throws BadJOSEException {

		throw new BadJOSEException("Unsecured (plain) JOSE objects are rejected");
	}


	@Override
	public Payload process(final JWSObject jwsObject, C context)
		throws BadJOSEException, JOSEException {

		if (getJWSKeySelector() == null) {
			throw new BadJOSEException("JWS object rejected: No JWS key selector is configured");
		}

		if (getJWSVerifierFactory() == null) {
			throw new BadJOSEException("JWS object rejected: No JWS verifier is configured");
		}

		List<? extends Key> keyCandidates = getJWSKeySelector().selectJWSKeys(jwsObject.getHeader(), context);

		if (keyCandidates == null || keyCandidates.isEmpty()) {
			throw new BadJOSEException("JWS object rejected: No matching key(s) found");
		}

		for (Key key: keyCandidates) {

			JWSVerifier verifier = getJWSVerifierFactory().createJWSVerifier(jwsObject.getHeader(), key);

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

		if (getJWEKeySelector() == null) {
			throw new BadJOSEException("JWE object rejected: No JWE key selector is configured");
		}

		if (getJWEDecrypterFactory() == null) {
			throw new BadJOSEException("JWE object rejected: No JWE decrypter is configured");
		}

		List<? extends Key> keyCandidates = getJWEKeySelector().selectJWEKeys(jweObject.getHeader(), context);

		if (keyCandidates == null || keyCandidates.isEmpty()) {
			throw new BadJOSEException("JWE object rejected: No matching key(s) found");
		}

		for (Key key: keyCandidates) {

			JWEDecrypter decrypter = getJWEDecrypterFactory().createJWEDecrypter(jweObject.getHeader(), key);

			if (decrypter == null) {
				continue;
			}

			try {
				jweObject.decrypt(decrypter);

			} catch (JOSEException e) {
				// Decryption failed
				throw new BadJWEException("JWE object rejected: " + e.getMessage(), e);
			}

			if ("JWT".equalsIgnoreCase(jweObject.getHeader().getContentType())) {

				// Handle nested signed JWT, see http://tools.ietf.org/html/rfc7519#section-5.2
				JWSObject nestedJWS = jweObject.getPayload().toJWSObject();

				if (nestedJWS == null) {
					// Cannot parse payload to JWS object, return original form
					return jweObject.getPayload();
				}

				return process(nestedJWS, context);
			}

			return jweObject.getPayload();
		}

		throw new BadJOSEException("JWE object rejected: No matching decrypter(s) found");
	}
}
