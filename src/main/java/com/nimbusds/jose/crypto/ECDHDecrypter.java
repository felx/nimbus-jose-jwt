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
 * @version $version$ (2015-05-21)
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


	public ECDHDecrypter(final ECPrivateKey privateKey)
		throws JOSEException {

		super(ECKey.Curve.forECParameterSpec(privateKey.getParams()));

		this.privateKey = privateKey;
	}


	public ECDHDecrypter(final ECKey ecJWK)
		throws JOSEException {

		super(ecJWK.getCurve());

		if (! ecJWK.isPrivate()) {
			throw new JOSEException("The EC JWK doesn't contain a private part");
		}

		this.privateKey = ecJWK.toECPrivateKey();
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

		critPolicy.ensureHeaderPasses(header);

		// Get ephemeral EC key
		ECKey ephemeralKey = header.getEphemeralPublicKey();

		if (ephemeralKey == null) {
			throw new JOSEException("Missing ephemeral public EC key \"epk\" JWE header parameter");
		}

		ECPublicKey ephemeralPublicKey = ephemeralKey.toECPublicKey();

		// Derive 'Z'
		SecretKey Z = ECDH.deriveSharedSecret(
			ephemeralPublicKey,
			privateKey,
			getJWEJCAProvider().getKeyEncryptionProvider());

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
