package com.nimbusds.jose.crypto;


import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.SecretKey;

import com.nimbusds.jose.CompressionAlgorithm;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWECryptoParts;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.ReadOnlyJWEHeader;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.DeflateUtils;



/**
 * Direct encrypter of {@link com.nimbusds.jose.JWEObject JWE objects} with a
 * shared symmetric key. This class is thread-safe.
 *
 * <p>Supports the following JWE algorithms:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#DIR}
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
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-04-15)
 */
public class DirectEncrypter extends DirectCryptoProvider implements JWEEncrypter {


	/**
	 * Random byte generator.
	 */
	private final SecureRandom randomGen;


	/**
	 * Creates a new direct encrypter.
	 *
	 * @param key The shared symmetric key. Must not be {@code null}.
	 *
	 * @throws JOSEException If the underlying secure random generator
	 *                       couldn't be instantiated.
	 */
	public DirectEncrypter(final byte[] key)
		throws JOSEException {

		super(key);

		try {
			randomGen = SecureRandom.getInstance("SHA1PRNG");

		} catch(NoSuchAlgorithmException e) {

			throw new JOSEException(e.getMessage(), e);
		}
	}


	/**
	 * Applies compression to the specified plain text if requested.
	 *
	 * @param readOnlyJWEHeader The JWE header. Must not be {@code null}.
	 * @param bytes             The plain text bytes. Must not be 
	 *                          {@code null}.
	 *
	 * @return The bytes to encrypt.
	 *
	 * @throws JOSEException If compression failed or the requested 
	 *                       compression algorithm is not supported.
	 */
	private static final byte[] applyCompression(final ReadOnlyJWEHeader readOnlyJWEHeader, final byte[] bytes)
		throws JOSEException {

		CompressionAlgorithm compressionAlg = readOnlyJWEHeader.getCompressionAlgorithm();

		if (compressionAlg == null) {

			return bytes;

		} else if (compressionAlg.equals(CompressionAlgorithm.DEF)) {

			try {
				return DeflateUtils.compress(bytes);

			} catch (Exception e) {

				throw new JOSEException("Couldn't compress plain text: " + e.getMessage(), e);
			}

		} else {

			throw new JOSEException("Unsupported compression algorithm: " + compressionAlg);
		}
	}


	@Override
	public JWECryptoParts encrypt(final ReadOnlyJWEHeader readOnlyJWEHeader, final byte[] bytes)
		throws JOSEException {

		JWEAlgorithm alg = readOnlyJWEHeader.getAlgorithm();

		if (! alg.equals(JWEAlgorithm.DIR)) {
			
			throw new JOSEException("Unsupported algorithm, must be \"dir\"");
		}

		EncryptionMethod enc = readOnlyJWEHeader.getEncryptionMethod();

		final Base64URL encryptedKey = null; // The second JWE part


		// Apply compression if instructed
		byte[] plainText = applyCompression(readOnlyJWEHeader, bytes);
		

		// Encrypt the plain text according to the JWE enc
		if (enc.equals(EncryptionMethod.A128CBC_HS256) || enc.equals(EncryptionMethod.A256CBC_HS512)) {

			byte[] epu = null;

			if (readOnlyJWEHeader.getEncryptionPartyUInfo() != null) {

				epu = readOnlyJWEHeader.getEncryptionPartyUInfo().decode();
			}

			byte[] epv = null;
			
			if (readOnlyJWEHeader.getEncryptionPartyVInfo() != null) {

				epv = readOnlyJWEHeader.getEncryptionPartyVInfo().decode();
			}

			SecretKey cek = ConcatKDF.generateCEK(cmk, enc, epu, epv);

			byte[] iv = AESCBC.generateIV(randomGen);

			byte[] cipherText = AESCBC.encrypt(cek, iv, plainText);

			SecretKey cik = ConcatKDF.generateCIK(cmk, enc, epu, epv);

			String macInput = readOnlyJWEHeader.toBase64URL().toString() + "." +
			                  /* encryptedKey omitted */ "." +
			                  Base64URL.encode(iv).toString() + "." +
			                  Base64URL.encode(cipherText);

			byte[] mac = HMAC.compute(cik, macInput.getBytes());

			return new JWECryptoParts(encryptedKey,  
				                  Base64URL.encode(iv), 
				                  Base64URL.encode(cipherText),
				                  Base64URL.encode(mac));

		} else if (enc.equals(EncryptionMethod.A128GCM) || enc.equals(EncryptionMethod.A256GCM)) {

			byte[] iv = AESGCM.generateIV(randomGen);

			// Compose the additional authenticated data
			String authDataString = readOnlyJWEHeader.toBase64URL().toString() + "." +
			                        /* encryptedKey omitted */ "." +
			                        Base64URL.encode(iv).toString();

			byte[] authData;

			try {
				authData = authDataString.getBytes("UTF-8");

			} catch (UnsupportedEncodingException e) {

				throw new JOSEException(e.getMessage(), e);
			}

			
			AESGCM.Result result = AESGCM.encrypt(cmk, iv, plainText, authData);

			return new JWECryptoParts(encryptedKey,  
				                  Base64URL.encode(iv), 
				                  Base64URL.encode(result.getCipherText()),
				                  Base64URL.encode(result.getAuthenticationTag()));

		} else {

			throw new JOSEException("Unsupported encryption method, must be A128CBC_HS256, A256CBC_HS512, A128GCM or A128GCM");
		}
	}
}