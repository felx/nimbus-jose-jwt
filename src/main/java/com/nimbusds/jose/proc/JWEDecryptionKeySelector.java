package com.nimbusds.jose.proc;


import java.security.Key;
import java.security.PrivateKey;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.sourcing.JWKSource;
import net.jcip.annotations.ThreadSafe;


/**
 * Key selector for decrypting JWE objects used in OpenID Connect.
 *
 * <p>Can be used to select RSA and EC key candidates for the decryption of:
 *
 * <ul>
 *     <li>Encrypted ID tokens
 *     <li>Encrypted JWT-encoded UserInfo responses
 *     <li>Encrypted OpenID request objects
 * </ul>
 */
@ThreadSafe
public class JWEDecryptionKeySelector extends AbstractJWKSelectorWithSource implements JWEKeySelector {


	/**
	 * The expected JWE algorithm.
	 */
	private final JWEAlgorithm jweAlg;


	/**
	 * The expected JWE encryption method.
	 */
	private final EncryptionMethod jweEnc;


	/**
	 * Ensures the specified JWE algorithm is RSA or EC based.
	 *
	 * @param jweAlg The JWE algorithm to check.
	 */
	private static void ensureAsymmetricEncryptionAlgorithm(final JWEAlgorithm jweAlg) {

		if (! JWEAlgorithm.Family.RSA.contains(jweAlg) && ! JWEAlgorithm.Family.ECDH_ES.contains(jweAlg)) {
			throw new IllegalArgumentException("The JWE algorithm must be RSA or EC based");
		}
	}


	/**
	 * Creates a new decryption key selector.
	 *
	 * @param id        Identifier for the JWE recipient, typically an
	 *                  OAuth 2.0 server issuer ID, or client ID. Must not
	 *                  be {@code null}.
	 * @param jweAlg    The expected JWE algorithm for the objects to be
	 *                  decrypted. Must not be {@code null}.
	 * @param jweEnc    The expected JWE encryption method for the objects
	 *                  to be decrypted. Must be RSA or EC based. Must not
	 *                  be {@code null}.
	 * @param jwkSource The JWK source. Must include the private keys and
	 *                  must not be {@code null}.
	 */
	public JWEDecryptionKeySelector(final String id,
					final JWEAlgorithm jweAlg,
					final EncryptionMethod jweEnc,
					final JWKSource jwkSource) {
		super(id, jwkSource);
		if (jweAlg == null) {
			throw new IllegalArgumentException("The JWE algorithm must not be null");
		}
		ensureAsymmetricEncryptionAlgorithm(jweAlg);
		this.jweAlg = jweAlg;
		if (jweEnc == null) {
			throw new IllegalArgumentException("The JWE encryption method must not be null");
		}
		this.jweEnc = jweEnc;
	}


	/**
	 * Returns the expected JWE algorithm.
	 *
	 * @return The expected JWE algorithm.
	 */
	public JWEAlgorithm getExpectedJWEAlgorithm() {
		return jweAlg;
	}


	/**
	 * The expected JWE encryption method.
	 *
	 * @return The expected JWE encryption method.
	 */
	public EncryptionMethod getExpectedJWEEncryptionMethod() {
		return jweEnc;
	}


	/**
	 * Creates a JWK matcher for the expected JWE algorithms and the
	 * specified JWE header.
	 *
	 * @param jweHeader The JWE header. Must not be {@code null}.
	 *
	 * @return The JWK matcher, {@code null} if none could be created.
	 */
	protected JWKMatcher createJWKMatcher(final JWEHeader jweHeader) {

		if (! getExpectedJWEAlgorithm().equals(jweHeader.getAlgorithm())) {
			return null;
		}

		if (! getExpectedJWEEncryptionMethod().equals(jweHeader.getEncryptionMethod())) {
			return null;
		}

		return new JWKMatcher.Builder()
			.keyType(KeyType.forAlgorithm(getExpectedJWEAlgorithm()))
			.keyID(jweHeader.getKeyID())
			.keyUses(KeyUse.ENCRYPTION, null)
			.algorithms(getExpectedJWEAlgorithm(), null)
			.build();
	}


	@Override
	public List<Key> selectJWEKeys(final JWEHeader jweHeader, final SecurityContext context) {

		if (! jweAlg.equals(jweHeader.getAlgorithm()) || ! jweEnc.equals(jweHeader.getEncryptionMethod())) {
			// Unexpected JWE alg or enc
			return Collections.emptyList();
		}

		JWKMatcher jwkMatcher = createJWKMatcher(jweHeader);
		List<JWK> jwkMatches = getJWKSource().get(getIdentifier(), new JWKSelector(jwkMatcher));

		List<Key> sanitizedKeyList = new LinkedList<>();

		for (Key key: KeyConverter.toJavaKeys(jwkMatches)) {
			if (key instanceof PrivateKey) {
				sanitizedKeyList.add(key);
			} // skip public keys
		}

		return sanitizedKeyList;
	}
}
