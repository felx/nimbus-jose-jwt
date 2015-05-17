package com.nimbusds.jose.crypto;


import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;

import javax.crypto.SecretKey;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;


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
 * @version $version$ (2015-05-16)
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
	public JWECryptoParts encrypt(final JWEHeader header, final byte[] clearText)
		throws JOSEException {

		final JWEAlgorithm alg = header.getAlgorithm();
		final ECDH.AlgorithmMode algMode = ECDH.resolveAlgorithmMode(alg);
		final EncryptionMethod enc = header.getEncryptionMethod();

		if (!supportedEncryptionMethods().contains(enc)) {
			throw new JOSEException("Unsupported JWT encryption method, must be ..."); // todo
		}

		// Generate ephemeral EC key pair on the same curve as the consumer's public key
		KeyPair ephemeralKeyPair = generateEphemeralKeyPair(publicKey.getParams());
		ECPublicKey ephemeralPublicKey = (ECPublicKey)ephemeralKeyPair.getPublic();
		ECPrivateKey ephemeralPrivateKey = (ECPrivateKey)ephemeralKeyPair.getPrivate();

		// Derive 'Z'
		SecretKey Z = ECDH.deriveSharedSecret(publicKey, ephemeralPrivateKey, getJWEJCAProvider().getGeneralProvider());

		// Derive shared key via concat KDF
		SecretKey sharedKey = ECDH.deriveSharedKey(header, Z, getConcatKDF());

		final SecretKey cek;
		final Base64URL encryptedKey; // The CEK encrypted (second JWE part)

		if (algMode.equals(ECDH.AlgorithmMode.DIRECT)) {
			cek = sharedKey;
			encryptedKey = null;
		} else if (algMode.equals(ECDH.AlgorithmMode.KW)) {
			cek = AES.generateKey(enc.cekBitLength(), getJWEJCAProvider().getSecureRandom());
			encryptedKey = Base64URL.encode(AESKW.encryptCEK(cek, sharedKey));
		} else {
			throw new JOSEException("Unexpected JWE ECDH algorithm mode: " + algMode);
		}

		// We need to work on the header
		JWEHeader updatedHeader = new JWEHeader.Builder(header).
			ephemeralPublicKey(new ECKey.Builder(ECKey.Curve.P_256, ephemeralPublicKey).build()).
			build(); // TODO ec curve

		return ContentCryptoProvider.encrypt(updatedHeader, clearText, cek, encryptedKey, getJWEJCAProvider());
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
