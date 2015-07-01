package com.nimbusds.jose.proc;


import java.security.Key;
import java.text.ParseException;
import java.util.List;
import java.util.ListIterator;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.*;


/**
 * Default processor of received {@link com.nimbusds.jose.JOSEObject}s.
 *
 * <p>Must be supplied with a {@link JWSKeySelector JWS key selector} to
 * determine the key candidate(s) for the signature verification. The exact key
 * selection procedure is application-specific and may involve key ID lookup, a
 * certificate check and / or other information supplied in the message
 * {@link SecurityContext context}.
 *
 * <p>Similarly, the processor must be supplied with a {@link JWEKeySelector
 * JWE key selector} if JWE messages are expected to be processed.
 *
 * <p>See sections 6 of RFC 7515 (JWS) and RFC 7516 (JWE) for guidelines on key
 * selection.
 *
 * <p>This processor comes with the default {@link DefaultJWSVerifierFactory
 * JWS verifier factory} and the default {@link DefaultJWEDecrypterFactory
 * JWE decrypter factory}; they can construct verifiers / decrypters for all
 * standard JOSE algorithms implemented by the library.
 *
 * <p>Note that for security reasons this processor is hardwired to reject
 * unsecured (plain) JOSE objects. Override the {@link #process(PlainObject,
 * SecurityContext)} if you need to handle plain JOSE objects as well.
 *
 * <p>To process JSON Web Tokens (JWTs) use the
 * {@link com.nimbusds.jwt.proc.DefaultJWTProcessor} class.
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-07-01
 */
@ThreadSafe
public class DefaultJOSEProcessor<C extends SecurityContext>
	extends BaseJOSEProcessor<C>
	implements JOSEProcessor<Payload, C>{

	@Override
	public Payload process(final String compactJOSE, final C context)
		throws ParseException, BadJOSEException, JOSEException {

		return process(JOSEObject.parse(compactJOSE), context);
	}


	@Override
	public Payload process(final JOSEObject joseObject, final C context)
		throws BadJOSEException, JOSEException {

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

		throw new BadJOSEException("Unsecured (plain) JOSE objects are rejected, extend class to handle");
	}


	@Override
	public Payload process(final JWSObject jwsObject, C context)
		throws BadJOSEException, JOSEException {

		if (getJWSKeySelector() == null) {
			// JWS key selector may have been deliberately omitted
			throw new BadJOSEException("JWS object rejected: No JWS key selector is configured");
		}

		if (getJWSVerifierFactory() == null) {
			throw new JOSEException("No JWS verifier is configured");
		}

		List<? extends Key> keyCandidates = getJWSKeySelector().selectJWSKeys(jwsObject.getHeader(), context);

		if (keyCandidates == null || keyCandidates.isEmpty()) {
			throw new BadJOSEException("JWS object rejected: No matching key(s) found");
		}

		ListIterator<? extends Key> it = keyCandidates.listIterator();

		while (it.hasNext()) {

			JWSVerifier verifier = getJWSVerifierFactory().createJWSVerifier(jwsObject.getHeader(), it.next());

			if (verifier == null) {
				continue;
			}

			final boolean validSignature = jwsObject.verify(verifier);

			if (validSignature) {
				return jwsObject.getPayload();
			}

			if (! it.hasNext()) {
				// No more keys to try out
				throw new BadJWSException("JWS object rejected: Invalid signature");
			}
		}

		throw new BadJOSEException("JWS object rejected: No matching verifier(s) found");
	}


	@Override
	public Payload process(final JWEObject jweObject, C context)
		throws BadJOSEException, JOSEException {

		if (getJWEKeySelector() == null) {
			// JWE key selector may have been deliberately omitted
			throw new BadJOSEException("JWE object rejected: No JWE key selector is configured");
		}

		if (getJWEDecrypterFactory() == null) {
			throw new JOSEException("No JWE decrypter is configured");
		}

		List<? extends Key> keyCandidates = getJWEKeySelector().selectJWEKeys(jweObject.getHeader(), context);

		if (keyCandidates == null || keyCandidates.isEmpty()) {
			throw new BadJOSEException("JWE object rejected: No matching key(s) found");
		}

		ListIterator<? extends Key> it = keyCandidates.listIterator();

		while (it.hasNext()) {

			JWEDecrypter decrypter = getJWEDecrypterFactory().createJWEDecrypter(jweObject.getHeader(), it.next());

			if (decrypter == null) {
				continue;
			}

			try {
				jweObject.decrypt(decrypter);

			} catch (JOSEException e) {

				if (it.hasNext()) {
					// Try next key
					continue;
				}

				// No more keys to try
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
