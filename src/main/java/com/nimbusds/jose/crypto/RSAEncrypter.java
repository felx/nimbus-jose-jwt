package com.nimbusds.jose.crypto;


import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.SecretKey;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWECryptoParts;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.ReadOnlyJWEHeader;
import com.nimbusds.jose.util.Base64URL;



/**
 * RSA encrypter of {@link com.nimbusds.jose.JWEObject JWE objects}. This class
 * is thread-safe.
 *
 * <p>Supports the following JWE algorithms:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#RSA1_5}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#RSA_OAEP}
 * </ul>
 *
 * <p>Supports the following encryption methods:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A128CBC_HS256}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A256CBC_HS512}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A128GCM}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A256GCM}
 * </ul>
 *
 * @author David Ortiz
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-03-24)
 */
public class RSAEncrypter extends RSACryptoProvider implements JWEEncrypter {


	/**
	 * Random byte generator.
	 */
	private final SecureRandom randomGen;


	/**
	 * The public RSA key.
	 */
	private final RSAPublicKey publicKey;


	/**
	 * Creates a new RSA encrypter.
	 *
	 * @param publicKey The public RSA key. Must not be {@code null}.
	 *
	 * @throws JOSEException If the underlying secure random generator
	 *                       couldn't be instantiated.
	 */
	public RSAEncrypter(final RSAPublicKey publicKey)
		throws JOSEException {

		if (publicKey == null) {

			throw new IllegalArgumentException("The public RSA key must not be null");
		}

		this.publicKey = publicKey;


		try {
			randomGen = SecureRandom.getInstance("SHA1PRNG");

		} catch(NoSuchAlgorithmException e) {

			throw new JOSEException(e.getMessage(), e);
		}
	}


	/**
	 * Gets the public RSA key.
	 *
	 * @return The public RSA key.
	 */
	public RSAPublicKey getPublicKey() {

		return publicKey;
	}


	@Override
	public JWECryptoParts encrypt(final ReadOnlyJWEHeader readOnlyJWEHeader, final byte[] bytes)
		throws JOSEException {

		JWEAlgorithm alg = readOnlyJWEHeader.getAlgorithm();
		EncryptionMethod enc = readOnlyJWEHeader.getEncryptionMethod();

		// Generate and encrypt the CMK according to the JWE alg
		final int keyLength = RSACryptoProvider.cmkBitLength(enc);

		SecretKey cmk = AES.generateAESCMK(keyLength);

		Base64URL encryptedKey = null; // The second JWE part

		if (alg.equals(JWEAlgorithm.RSA1_5)) {

			encryptedKey = Base64URL.encode(RSA1_5.encryptCMK(publicKey, cmk));

		} else if (alg.equals(JWEAlgorithm.RSA_OAEP)) {

			encryptedKey = Base64URL.encode(RSA_OAEP.encryptCMK(publicKey, cmk));

		} else {

			throw new JOSEException("Unsupported algorithm, must be RSA1_5 or RSA_OAEP");
		}

		if (encryptedKey == null ) {

			throw new JOSEException("Couldn't generate encrypted key");
		}

		// Encrypt the plain text according to the JWE enc
		if (enc.equals(EncryptionMethod.A128CBC_HS256) || enc.equals(EncryptionMethod.A256CBC_HS512)) {

			Digest kdfDigest;

			if (enc.equals(EncryptionMethod.A128CBC_HS256)) {

				kdfDigest = new SHA256Digest();

			} else {

				kdfDigest = new SHA512Digest();
			}

			SecretKey cek = CEK.generate(encryptedKey.decode(), cekBitLength(enc), kdfDigest, enc.toString());

			byte[] iv = AESCBC.generateIV(randomGen);

			byte[] cipherText = AESCBC.encrypt(cek, bytes, iv);

			SecretKey cik = CIK.generate(encryptedKey.decode(), cikBitLength(enc), kdfDigest, enc.toString());

			String authDataString = readOnlyJWEHeader.toBase64URL().toString() + "." +
			                        encryptedKey.toString() + "." +
			                        Base64URL.encode(iv).toString() + "." +
			                        Base64URL.encode(cipherText);

			byte[] mac = HMAC.compute(cik, authDataString.getBytes());

			return new JWECryptoParts(encryptedKey,  
				                  Base64URL.encode(iv), 
				                  Base64URL.encode(cipherText),
				                  Base64URL.encode(mac));

		} else if (enc.equals(EncryptionMethod.A128GCM) || enc.equals(EncryptionMethod.A256GCM)) {

			byte[] iv = AESGCM.generateIV(randomGen);

			String authDataString = readOnlyJWEHeader.toBase64URL().toString() + "." +
			                        encryptedKey.toString() + "." +
			                        Base64URL.encode(iv).toString();


			byte[] authData;

			try {
				authData = authDataString.getBytes("UTF-8");

			} catch (UnsupportedEncodingException e) {

				throw new JOSEException(e.getMessage(), e);
			}

			
			AESGCM.Result result = AESGCM.encrypt(cmk, bytes, authData, iv);

			return new JWECryptoParts(encryptedKey,  
				                  Base64URL.encode(iv), 
				                  Base64URL.encode(result.getCipherText()),
				                  Base64URL.encode(result.getAuthenticationTag()));

		} else {

			throw new JOSEException("Unsupported encryption method, must be A128CBC_HS256, A256CBC_HS512, A128GCM or A128GCM");
		}
	}
}