package com.nimbusds.jose.crypto;


import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Set;

import javax.crypto.SecretKey;

import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;


/**
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-05-16)
 */
public class ECDHDecrypter extends ECDHCryptoProvider implements JWEDecrypter, CriticalHeaderParamsAware {


	/**
	 * The private EC key.
	 */
	private final ECPrivateKey privateKey;


	/**
	 * The critical header policy.
	 */
	private final CriticalHeaderParamsDeferral critPolicy = new CriticalHeaderParamsDeferral();


	public ECDHDecrypter(final ECPrivateKey privateKey) {

		// TODO check curve

		this.privateKey = privateKey;
	}


	@Override
	public Set<String> getProcessedCriticalHeaderParams() {

		return critPolicy.getProcessedCriticalHeaderParams();
	}


	@Override
	public Set<String> getDeferredCriticalHeaderParams() {

		return critPolicy.getProcessedCriticalHeaderParams();
	}


	@Override
	public byte[] decrypt(final JWEHeader header,
			      final Base64URL encryptedKey,
			      final Base64URL iv,
			      final Base64URL cipherText,
			      final Base64URL authTag)
		throws JOSEException {

		final JWEAlgorithm alg = header.getAlgorithm();
		final ECDH.AlgorithmMode algMode = ECDH.resolveAlgorithmMode(alg);
		final EncryptionMethod enc = header.getEncryptionMethod();

		if (! critPolicy.headerPasses(header)) {
			throw new JOSEException("Unsupported critical header parameter(s)");
		}

		// Get ephemeral EC key
		ECKey ephemeralKey = header.getEphemeralPublicKey();

		if (ephemeralKey == null) {
			throw new JOSEException("Missing ephemeral public EC key \"epk\" header parameter");
		}

		ECPublicKey ephemeralPublicKey = ephemeralKey.toECPublicKey();

		// Derive 'Z'
		SecretKey Z = ECDH.deriveSharedSecret(ephemeralPublicKey, privateKey, getJWEJCAProvider().getGeneralProvider());

		// Derive shared key via concat KDF
		SecretKey sharedKey = ECDH.deriveSharedKey(header, Z, getConcatKDF());

		final SecretKey cek;

		if (algMode.equals(ECDH.AlgorithmMode.DIRECT)) {
			cek = sharedKey;
		} else if (algMode.equals(ECDH.AlgorithmMode.KW)) {
			if (encryptedKey == null) {
				throw new JOSEException("Missing JWE encrypted key");
			}
			cek = AESKW.decryptCEK(sharedKey, encryptedKey.decode());
		} else {
			throw new JOSEException("Unexpected JWE ECDH algorithm mode: " + algMode);
		}

		return ContentCryptoProvider.decrypt(header, encryptedKey, iv, cipherText, authTag, cek, getJWEJCAProvider());
	}
}
