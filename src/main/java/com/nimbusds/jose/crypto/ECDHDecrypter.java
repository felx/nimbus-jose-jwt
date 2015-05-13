package com.nimbusds.jose.crypto;


import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Set;

import javax.crypto.SecretKey;

import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.StringUtils;


/**
 * Created by vd on 15-5-13.
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
		SecretKey Z = ECDH.deriveSharedSecret(ephemeralPublicKey, privateKey, getJWEJCAProvider().getProvider());

		System.out.println("Z: " + Base64URL.encode(Z.getEncoded()));

		final int sharedKeyLength = sharedKeyLength(alg, enc);

		ConcatKDF concatKDF = new ConcatKDF("SHA-256");

		SecretKey sharedKey = concatKDF.deriveKey(
			Z,
			sharedKeyLength,
			ConcatKDF.encodeStringData(header.getEncryptionMethod().getName()),
			ConcatKDF.encodeDataWithLength(header.getAgreementPartyUInfo()),
			ConcatKDF.encodeDataWithLength(header.getAgreementPartyVInfo()),
			ConcatKDF.encodeIntData(sharedKeyLength),
			ConcatKDF.encodeNoData());

		System.out.println("Shared key: " + Base64URL.encode(sharedKey.getEncoded()));

		final SecretKey cek;

		if (alg.equals(JWEAlgorithm.ECDH_ES)) {

			// Direct ephemeral static
			cek = sharedKey;

		} else if (alg.equals(JWEAlgorithm.ECDH_ES_A128KW)
			|| alg.equals(JWEAlgorithm.ECDH_ES_A192KW)
			|| alg.equals(JWEAlgorithm.ECDH_ES_A256KW)) {

			if (encryptedKey == null) {
				throw new JOSEException("Missing JWE encrypted key");
			}

			cek = AESKW.decryptCEK(sharedKey, encryptedKey.decode());

		} else {
			throw new JOSEException("Unexpected JWE algorithm: " + alg);
		}

		// Compose the AAD
		byte[] aad = StringUtils.toByteArray(header.toBase64URL().toString());

		// Decrypt the cipher text according to the JWE enc

		byte[] plainText;

		if (enc.equals(EncryptionMethod.A128CBC_HS256) ||
			enc.equals(EncryptionMethod.A192CBC_HS384) ||
			enc.equals(EncryptionMethod.A256CBC_HS512)) {

			plainText = AESCBC.decryptAuthenticated(
				cek,
				iv.decode(),
				cipherText.decode(),
				aad,
				authTag.decode(),
				getJWEJCAProvider().getContentEncryptionProvider(),
				getJWEJCAProvider().getMACProvider());

		} else if (enc.equals(EncryptionMethod.A128GCM) ||
			enc.equals(EncryptionMethod.A192GCM) ||
			enc.equals(EncryptionMethod.A256GCM)) {

			plainText = AESGCM.decrypt(
				cek,
				iv.decode(),
				cipherText.decode(),
				aad,
				authTag.decode(),
				getJWEJCAProvider().getContentEncryptionProvider());

		} else if (enc.equals(EncryptionMethod.A128CBC_HS256_DEPRECATED) ||
			enc.equals(EncryptionMethod.A256CBC_HS512_DEPRECATED)) {

			plainText = AESCBC.decryptWithConcatKDF(
				header,
				cek,
				encryptedKey,
				iv,
				cipherText,
				authTag,
				getJWEJCAProvider().getContentEncryptionProvider(),
				getJWEJCAProvider().getMACProvider());

		} else {

			throw new JOSEException("Unsupported encryption method, must be A128CBC_HS256, A192CBC_HS384, A256CBC_HS512, A128GCM, A192GCM or A256GCM");
		}


		// Apply decompression if requested
		return DeflateHelper.applyDecompression(header, plainText);
	}
}
