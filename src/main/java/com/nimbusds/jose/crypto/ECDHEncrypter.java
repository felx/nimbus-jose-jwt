package com.nimbusds.jose.crypto;


import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECParameterSpec;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.ECKey;
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
 * @version $version$ (2015-05-11)
 */
@ThreadSafe
public class ECDHEncrypter extends ECDHCryptoProvider {


	/**
	 * Generates a new ephemeral EC key pair with the specified curve.
	 *
	 * @param curve The curve. Must be supported and not {@code null}.
	 *
	 * @return The EC key pair.
	 *
	 * @throws JOSEException If the EC key pair couldn't be generated.
	 */
	private KeyPair generateEphemeralKeyPair(final ECKey.Curve curve)
		throws JOSEException {

		ECParameterSpec ecParameterSpec = curve.toECParameterSpec();

		if (ecParameterSpec == null) {
			throw new JOSEException("Unsupported / unknown Elliptic Curve: " + curve);
		}

		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");  // TODO Provider
			generator.initialize(ecParameterSpec);
			return generator.generateKeyPair();
		} catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
			throw new JOSEException("Couldn't generate ephemeral EC key pair: " + e.getMessage(), e);
		}
	}
}
