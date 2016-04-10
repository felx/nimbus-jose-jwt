package com.nimbusds.jose.proc;


import java.security.Key;
import java.security.PublicKey;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import javax.crypto.SecretKey;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.sourcing.JWKSource;
import net.jcip.annotations.ThreadSafe;


/**
 * Key selector for verifying JWS objects used in OpenID Connect.
 *
 * <p>Can be used to select RSA and EC key candidates for the verification of:
 *
 * <ul>
 *     <li>Signed ID tokens
 *     <li>Signed JWT-encoded UserInfo responses
 *     <li>Signed OpenID request objects
 * </ul>
 *
 * <p>Client secret candidates for the verification of:
 *
 * <ul>
 *     <li>HMAC ID tokens
 *     <li>HMAC JWT-encoded UserInfo responses
 *     <li>HMAC OpenID request objects
 * </ul>
 */
@ThreadSafe
public class JWSVerificationKeySelector extends AbstractJWKSelectorWithSource implements JWSKeySelector {


	/**
	 * The expected JWS algorithm.
	 */
	private final JWSAlgorithm jwsAlg;


	/**
	 * Creates a new JWS verification key selector.
	 *
	 * @param id        Identifier for the JWS originator, typically an
	 *                  OAuth 2.0 server issuer ID, or client ID. Must not
	 *                  be {@code null}.
	 * @param jwsAlg    The expected JWS algorithm for the objects to be
	 *                  verified. Must not be {@code null}.
	 * @param jwkSource The JWK source. Must not be {@code null}.
	 */
	public JWSVerificationKeySelector(final String id, final JWSAlgorithm jwsAlg, final JWKSource jwkSource) {
		super(id, jwkSource);
		if (jwsAlg == null) {
			throw new IllegalArgumentException("The JWS algorithm must not be null");
		}
		this.jwsAlg = jwsAlg;
	}


	/**
	 * Returns the expected JWS algorithm.
	 *
	 * @return The expected JWS algorithm.
	 */
	public JWSAlgorithm getExpectedJWSAlgorithm() {

		return jwsAlg;
	}


	/**
	 * Creates a JWK matcher for the expected JWS algorithm and the
	 * specified JWS header.
	 *
	 * @param jwsHeader The JWS header. Must not be {@code null}.
	 *
	 * @return The JWK matcher, {@code null} if none could be created.
	 */
	protected JWKMatcher createJWKMatcher(final JWSHeader jwsHeader) {

		if (! getExpectedJWSAlgorithm().equals(jwsHeader.getAlgorithm())) {
			// Unexpected JWS alg
			return null;
		} else if (JWSAlgorithm.Family.RSA.contains(getExpectedJWSAlgorithm()) || JWSAlgorithm.Family.EC.contains(getExpectedJWSAlgorithm())) {
			// RSA or EC key matcher
			return new JWKMatcher.Builder()
					.keyType(KeyType.forAlgorithm(getExpectedJWSAlgorithm()))
					.keyID(jwsHeader.getKeyID())
					.keyUses(KeyUse.SIGNATURE, null)
					.algorithms(getExpectedJWSAlgorithm(), null)
					.build();
		} else if (JWSAlgorithm.Family.HMAC_SHA.contains(getExpectedJWSAlgorithm())) {
			// Client secret matcher
			return new JWKMatcher.Builder()
					.keyType(KeyType.forAlgorithm(getExpectedJWSAlgorithm()))
					.keyID(jwsHeader.getKeyID())
					.privateOnly(true)
					.algorithms(getExpectedJWSAlgorithm(), null)
					.build();
		} else {
			return null; // Unsupported algorithm
		}
	}


	@Override
	public List<Key> selectJWSKeys(final JWSHeader jwsHeader, final SecurityContext context) {

		if (! jwsAlg.equals(jwsHeader.getAlgorithm())) {
			// Unexpected JWS alg
			return Collections.emptyList();
		}

		JWKMatcher jwkMatcher = createJWKMatcher(jwsHeader);
		if (jwkMatcher == null) {
			return Collections.emptyList();
		}

		List<JWK> jwkMatches = getJWKSource().get(getIdentifier(), new JWKSelector(jwkMatcher));

		List<Key> sanitizedKeyList = new LinkedList<>();

		for (Key key: KeyConverter.toJavaKeys(jwkMatches)) {
			if (key instanceof PublicKey || key instanceof SecretKey) {
				sanitizedKeyList.add(key);
			} // skip asymmetric private keys
		}

		return sanitizedKeyList;
	}
}
