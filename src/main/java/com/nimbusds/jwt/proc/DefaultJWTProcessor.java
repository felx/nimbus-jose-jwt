package com.nimbusds.jwt.proc;


import java.security.Key;
import java.text.ParseException;
import java.util.List;
import java.util.ListIterator;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.factories.DefaultJWEDecrypterFactory;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.proc.*;
import com.nimbusds.jwt.*;


/**
 * Default processor of {@link com.nimbusds.jwt.PlainJWT unsecured} (plain),
 * {@link com.nimbusds.jwt.SignedJWT signed} and
 * {@link com.nimbusds.jwt.EncryptedJWT encrypted} JSON Web Tokens (JWTs).
 *
 * <p>Must be configured with the following:
 *
 * <ol>
 *     <li>To process signed JWTs: A {@link JWSKeySelector JWS key selector}
 *     to determine the key candidate(s) for the signature verification. The
 *     key selection procedure is application-specific and may involve key ID
 *     lookup, a certificate check and / or other information supplied in the
 *     message {@link SecurityContext context}.</li>
 *
 *     <li>To process encrypted JWTs: A {@link JWEKeySelector JWE key selector}
 *     to determine the key candidate(s) for decryption. The key selection
 *     procedure is application-specific and may involve key ID lookup, a
 *     certificate check and / or other information supplied in the message
 *     {@link SecurityContext context}.</li>
 * </ol>
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
 * unsecured (plain) JWTs. Override the {@link #process(PlainJWT, SecurityContext)}
 * if you need to handle plain JWTs as well.
 *
 * <p>A {@link DefaultJWTClaimsVerifier default JWT claims verifier} is
 * provided, to perform a minimal check of the claims after a successful JWS
 * verification / JWE decryption. It checks the token expiration (exp) and
 * not-before (nbf) timestamps if these are present. The default JWT claims
 * verifier may be extended to perform additional checks, such as issuer and
 * subject acceptance.
 *
 * <p>To process generic JOSE objects (with arbitrary payloads) use the
 * {@link com.nimbusds.jose.proc.DefaultJOSEProcessor} class.
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-08-27
 */
public class DefaultJWTProcessor<C extends SecurityContext>
	implements ConfigurableJWTProcessor<C> {


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
	 * The claims verifier.
	 */
	private JWTClaimsVerifier claimsVerifier = new DefaultJWTClaimsVerifier();


	@Override
	public JWSKeySelector<C> getJWSKeySelector() {

		return jwsKeySelector;
	}


	@Override
	public void setJWSKeySelector(final JWSKeySelector<C> jwsKeySelector) {

		this.jwsKeySelector = jwsKeySelector;
	}


	@Override
	public JWEKeySelector<C> getJWEKeySelector() {

		return jweKeySelector;
	}


	@Override
	public void setJWEKeySelector(final JWEKeySelector<C> jweKeySelector) {

		this.jweKeySelector = jweKeySelector;
	}


	@Override
	public JWSVerifierFactory getJWSVerifierFactory() {

		return jwsVerifierFactory;
	}


	@Override
	public void setJWSVerifierFactory(final JWSVerifierFactory factory) {

		jwsVerifierFactory = factory;
	}


	@Override
	public JWEDecrypterFactory getJWEDecrypterFactory() {

		return jweDecrypterFactory;
	}


	@Override
	public void setJWEDecrypterFactory(final JWEDecrypterFactory factory) {

		jweDecrypterFactory = factory;
	}


	@Override
	public JWTClaimsVerifier getJWTClaimsVerifier() {

		return claimsVerifier;
	}


	@Override
	public void setJWTClaimsVerifier(final JWTClaimsVerifier claimsVerifier) {

		this.claimsVerifier = claimsVerifier;
	}


	/**
	 * Verifies the claims of the specified JWT.
	 *
	 * @param jwt The JWT. Must be in a state which allows the claims to
	 *            be extracted.
	 *
	 * @return The JWT claims set.
	 *
	 * @throws BadJWTException If the JWT claims are invalid or rejected.
	 */
	private JWTClaimsSet verifyAndReturnClaims(final JWT jwt)
		throws BadJWTException {

		JWTClaimsSet claimsSet;

		try {
			claimsSet = jwt.getJWTClaimsSet();

		} catch (ParseException e) {
			// Payload not a JSON object
			throw new BadJWTException(e.getMessage(), e);
		}

		if (getJWTClaimsVerifier() != null) {
			getJWTClaimsVerifier().verify(claimsSet);
		}

		return claimsSet;
	}


	@Override
	public JWTClaimsSet process(final String jwtString, final C context)
		throws ParseException, BadJOSEException, JOSEException {

		return process(JWTParser.parse(jwtString), context);
	}


	@Override
	public JWTClaimsSet process(final JWT jwt, final C context)
		throws BadJOSEException, JOSEException {

		if (jwt instanceof SignedJWT) {
			return process((SignedJWT)jwt, context);
		}

		if (jwt instanceof EncryptedJWT) {
			return process((EncryptedJWT)jwt, context);
		}

		if (jwt instanceof PlainJWT) {
			return process((PlainJWT)jwt, context);
		}

		// Should never happen
		throw new JOSEException("Unexpected JWT object type: " + jwt.getClass());
	}


	@Override
	public JWTClaimsSet process(final PlainJWT plainJWT, final C context)
		throws BadJOSEException, JOSEException {

		verifyAndReturnClaims(plainJWT); // just check claims, no return

		throw new BadJOSEException("Unsecured (plain) JWTs are rejected, extend class to handle");
	}


	@Override
	public JWTClaimsSet process(final SignedJWT signedJWT, final C context)
		throws BadJOSEException, JOSEException {

		if (getJWSKeySelector() == null) {
			// JWS key selector may have been deliberately omitted
			throw new BadJOSEException("Signed JWT rejected: No JWS key selector is configured");
		}

		if (getJWSVerifierFactory() == null) {
			throw new JOSEException("No JWS verifier is configured");
		}

		List<? extends Key> keyCandidates = getJWSKeySelector().selectJWSKeys(signedJWT.getHeader(), context);

		if (keyCandidates == null || keyCandidates.isEmpty()) {
			throw new BadJOSEException("Signed JWT rejected: No matching key(s) found");
		}

		ListIterator<? extends Key> it = keyCandidates.listIterator();

		while (it.hasNext()) {

			JWSVerifier verifier = getJWSVerifierFactory().createJWSVerifier(signedJWT.getHeader(), it.next());

			if (verifier == null) {
				continue;
			}

			final boolean validSignature = signedJWT.verify(verifier);

			if (validSignature) {
				return verifyAndReturnClaims(signedJWT);
			}

			if (! it.hasNext()) {
				// No more keys to try out
				throw new BadJWSException("Signed JWT rejected: Invalid signature");
			}
		}

		throw new BadJOSEException("JWS object rejected: No matching verifier(s) found");
	}


	@Override
	public JWTClaimsSet process(final EncryptedJWT encryptedJWT, final C context)
		throws BadJOSEException, JOSEException {

		if (getJWEKeySelector() == null) {
			// JWE key selector may have been deliberately omitted
			throw new BadJOSEException("Encrypted JWT rejected: No JWE key selector is configured");
		}

		if (getJWEDecrypterFactory() == null) {
			throw new JOSEException("No JWE decrypter is configured");
		}

		List<? extends Key> keyCandidates = getJWEKeySelector().selectJWEKeys(encryptedJWT.getHeader(), context);

		if (keyCandidates == null || keyCandidates.isEmpty()) {
			throw new BadJOSEException("Encrypted JWT rejected: No matching key(s) found");
		}

		ListIterator<? extends Key> it = keyCandidates.listIterator();

		while (it.hasNext()) {

			JWEDecrypter decrypter = getJWEDecrypterFactory().createJWEDecrypter(encryptedJWT.getHeader(), it.next());

			if (decrypter == null) {
				continue;
			}

			try {
				encryptedJWT.decrypt(decrypter);

			} catch (JOSEException e) {

				if (it.hasNext()) {
					// Try next key
					continue;
				}

				// No more keys to try
				throw new BadJWEException("Encrypted JWT rejected: " + e.getMessage(), e);
			}

			if ("JWT".equalsIgnoreCase(encryptedJWT.getHeader().getContentType())) {

				// Handle nested signed JWT, see http://tools.ietf.org/html/rfc7519#section-5.2
				SignedJWT nestedJWT = encryptedJWT.getPayload().toSignedJWT();

				if (nestedJWT == null) {
					// Cannot parse payload to signed JWT
					throw new BadJWTException("The payload is not a nested JWT");
				}

				return process(nestedJWT, context);
			}

			return verifyAndReturnClaims(encryptedJWT);
		}

		throw new BadJOSEException("Encrypted JWT rejected: No matching decrypter(s) found");
	}
}
