package com.nimbusds.jose.crypto;


import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.StringUtils;
import net.jcip.annotations.ThreadSafe;


/**
 * Elliptic Curve Diffie-Hellman encrypter of
 * {@link com.nimbusds.jose.JWEObject JWE objects}. This class is thread-safe.
 *
 * <p>Supports the following JSON Web Algorithms (JWAs):
 *
 * <ul>
 *      <li>{@link com.nimbusds.jose.JWEAlgorithm#ECDH_ES}
 *      <li>{@link com.nimbusds.jose.JWEAlgorithm#ECDH_ES_A128KW}
 *      <li>{@link com.nimbusds.jose.JWEAlgorithm#ECDH_ES_A192KW}
 *      <li>{@link com.nimbusds.jose.JWEAlgorithm#ECDH_ES_A256KW}
 * </ul>
 *
 * <p>Supports the following encryption methods:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A128CBC_HS256}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A192CBC_HS384}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A256CBC_HS512}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A128GCM}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A192GCM}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A256GCM}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A128CBC_HS256_DEPRECATED}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A256CBC_HS512_DEPRECATED}
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-05-12)
 */
@ThreadSafe
public class ECDHEncrypter extends ECDHCryptoProvider implements JWEEncrypter {


	/**
	 * The public EC key.
	 */
	private final ECPublicKey publicKey;


	/**
	 * Creates a new Elliptic Curve Diffie-Hellman encrypter.
	 *
	 * @param publicKey The public EC key. Must not be {@code null}.
	 */
	public ECDHEncrypter(final ECPublicKey publicKey) {

		// TODO check curve

		this.publicKey = publicKey;
	}


	/**
	 * Creates a new Elliptic Curve Diffie-Hellman encrypter.
	 *
	 * @param ecJWK The EC JSON Web Key (JWK). Must not be {@code null}.
	 *
	 * @throws JOSEException If the EC JWK is invalid.
	 */
	public ECDHEncrypter(final ECKey ecJWK)
		throws JOSEException {

		this.publicKey = ecJWK.toECPublicKey();
	}


	@Override
	public JWECryptoParts encrypt(final JWEHeader header, final byte[] bytes)
		throws JOSEException {

		final JWEAlgorithm alg = header.getAlgorithm();

		if (!supportedJWEAlgorithms().contains(alg)) {
			throw new JOSEException("Unsupported JWE algorithm, must be \"dir\""); // todo
		}

		final EncryptionMethod enc = header.getEncryptionMethod();

		if (!supportedEncryptionMethods().contains(enc)) {
			throw new JOSEException("Unsupported JWT encryption method, must be ..."); // todo
		}

		// Generate ephemeral EC key pair on the same curve as the consumer's public key
		KeyPair ephemeralKeyPair = generateEphemeralKeyPair(publicKey.getParams());
		ECPublicKey ephemeralPublicKey = (ECPublicKey)ephemeralKeyPair.getPublic();
		ECPrivateKey ephemeralPrivateKey = (ECPrivateKey)ephemeralKeyPair.getPrivate();

		// Derive 'Z'
		SecretKey Z = ECDH.deriveSharedSecret(publicKey, ephemeralPrivateKey, getJWEJCAProvider().getProvider());

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

		final SecretKey cek;
		final Base64URL encryptedKey; // The second JWE part

		if (alg.equals(JWEAlgorithm.ECDH_ES)) {

			// Direct ephemeral static
			cek = sharedKey;
			encryptedKey = null;

		} else if (alg.equals(JWEAlgorithm.ECDH_ES_A128KW)
			|| alg.equals(JWEAlgorithm.ECDH_ES_A192KW)
			|| alg.equals(JWEAlgorithm.ECDH_ES_A256KW)) {

			SecureRandom randomGen = getJWEJCAProvider().getSecureRandom();
			cek = AES.generateKey(enc.cekBitLength(), randomGen);
			encryptedKey = Base64URL.encode(AESKW.encryptCEK(sharedKey, sharedKey));
		} else {
			throw new JOSEException("Unexpected JWE algorithm: " + alg);
		}

		// We need to work on the header
		JWEHeader updatedHeader = new JWEHeader.Builder(header).
			ephemeralPublicKey(new ECKey.Builder(ECKey.Curve.P_256, ephemeralPublicKey).build()).
			build(); // TODO ec curve

		// Apply compression if instructed
		byte[] plainText = DeflateHelper.applyCompression(updatedHeader, bytes);

		// Compose the AAD
		byte[] aad = StringUtils.toByteArray(updatedHeader.toBase64URL().toString());

		// Encrypt the plain text according to the JWE enc
		byte[] iv;
		AuthenticatedCipherText authCipherText;

		if (enc.equals(EncryptionMethod.A128CBC_HS256) ||
			enc.equals(EncryptionMethod.A192CBC_HS384) ||
			enc.equals(EncryptionMethod.A256CBC_HS512)    ) {

			iv = AESCBC.generateIV(getJWEJCAProvider().getSecureRandom());

			authCipherText = AESCBC.encryptAuthenticated(
				cek, iv, plainText, aad,
				getJWEJCAProvider().getContentEncryptionProvider(), getJWEJCAProvider().getMACProvider());

		} else if (enc.equals(EncryptionMethod.A128GCM) ||
			enc.equals(EncryptionMethod.A192GCM) ||
			enc.equals(EncryptionMethod.A256GCM)    ) {

			iv = AESGCM.generateIV(getJWEJCAProvider().getSecureRandom());

			authCipherText = AESGCM.encrypt(
				cek, iv, plainText, aad,
				getJWEJCAProvider().getContentEncryptionProvider());

		} else if (enc.equals(EncryptionMethod.A128CBC_HS256_DEPRECATED) ||
			enc.equals(EncryptionMethod.A256CBC_HS512_DEPRECATED)    ) {

			iv = AESCBC.generateIV(getJWEJCAProvider().getSecureRandom());

			authCipherText = AESCBC.encryptWithConcatKDF(
				updatedHeader, cek, encryptedKey, iv, plainText,
				getJWEJCAProvider().getContentEncryptionProvider(), getJWEJCAProvider().getMACProvider());

		} else {

			throw new JOSEException("Unsupported encryption method, must be A128CBC_HS256, A192CBC_HS384, A256CBC_HS512, A128GCM, A192GCM or A256GCM");
		}

		return new JWECryptoParts(updatedHeader,
			encryptedKey,
			Base64URL.encode(iv),
			Base64URL.encode(authCipherText.getCipherText()),
			Base64URL.encode(authCipherText.getAuthenticationTag()));
	}


	/**
	 * Generates a new ephemeral EC key pair with the specified curve.
	 *
	 * @param ecParameterSpec The EC key spec. Must not be {@code null}.
	 *
	 * @return The EC key pair.
	 *
	 * @throws JOSEException If the EC key pair couldn't be generated.
	 */
	private static KeyPair generateEphemeralKeyPair(final ECParameterSpec ecParameterSpec)
		throws JOSEException {

		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");  // TODO Provider
			generator.initialize(ecParameterSpec);
			return generator.generateKeyPair();
		} catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
			throw new JOSEException("Couldn't generate ephemeral EC key pair: " + e.getMessage(), e);
		}
	}
}
