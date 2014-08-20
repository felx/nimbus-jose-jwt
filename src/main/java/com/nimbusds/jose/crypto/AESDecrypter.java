package com.nimbusds.jose.crypto;


import java.util.HashSet;
import java.util.Set;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.StringUtils;


/**
 * AES decrypter of {@link com.nimbusds.jose.JWEObject JWE objects}. This class
 * is thread-safe.
 *
 * <p>Supports the following JWE algorithms:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#A128KW}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#A192KW}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#A256KW}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#A128GCMKW}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#A192GCMKW}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#A256GCMKW}
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
 * <p>Accepts all {@link com.nimbusds.jose.JWEHeader#getRegisteredParameterNames
 * registered JWE header parameters}. Use {@link #setAcceptedAlgorithms} and
 * {@link #setAcceptedEncryptionMethods} to restrict the acceptable JWE
 * algorithms and encryption methods.
 *
 * @author Melisa Halsband 
 * @version $version$ (2014-08-19)
 */
public class AESDecrypter extends AESCryptoProvider implements JWEDecrypter {


	/**
	 * The accepted JWE algorithms.
	 */
	private Set<JWEAlgorithm> acceptedAlgs;


	/**
	 * The accepted encryption methods.
	 */
	private Set<EncryptionMethod> acceptedEncs =
		new HashSet<>(supportedEncryptionMethods());


	/**
	 * The critical header parameter checker.
	 */
	private final CriticalHeaderParameterChecker critParamChecker =
		new CriticalHeaderParameterChecker();


	/**
	 * The key encrypting key.
	 */
	private final SecretKey kek;


	/**
	 * Creates a new AES decrypter.
	 *
	 * @param kek The Key Encrypting Key. Must be 128 bits (16 bytes), 192
	 *            bits (24 bytes) or 256 bits (32 bytes). Must not be
	 *            {@code null}.
	 *
	 * @throws IllegalArgumentException If called with a null parameter or
	 *                                  unsupported key length
	 */
	public AESDecrypter(final SecretKey kek) {

		if (kek == null) {

			throw new IllegalArgumentException("The Key Encrypting Key must not be null");
		}

		this.kek = kek;

		acceptedAlgs = compatibleAlgorithms();

		if (acceptedAlgs == null){
			throw new IllegalArgumentException("The Key Encrypting Key must be 128, 192 or 256 bits long");
		}
	}


	/**
	 * Creates a new AES decrypter.
	 *
	 * @param keyBytes The Key Encrypting Key, as a byte array. Must be 128
	 *                 bits (16 bytes), 192 bits (24 bytes) or 256 bits (32
	 *                 bytes). Must not be {@code null}.
	 *
	 * @throws IllegalArgumentException If called with a null parameter or
	 *                                  unsupported key length
	 */
	public AESDecrypter(final byte[] keyBytes)
		throws IllegalArgumentException {

		this(new SecretKeySpec(keyBytes, "AES"));
	}


	/**
	 * Returns the JWK algorithms compatible with the key size.
	 *
	 * @return The set of compatible algorithms.
	 */
	public Set<JWEAlgorithm> compatibleAlgorithms() {

		return COMPATIBLE_ALGORITHMS.get(kek.getEncoded().length);
	}


	/**
	 * Gets the Key Encrypting Key.
	 *
	 * @return The Key Encrypting Key.
	 */
	public SecretKey getKey() {

		return kek;
	}


	@Override
	public Set<JWEAlgorithm> getAcceptedAlgorithms() {

		return acceptedAlgs;
	}


	@Override
	public void setAcceptedAlgorithms(final Set<JWEAlgorithm> acceptedAlgs) {

		if (acceptedAlgs == null) {
			throw new IllegalArgumentException("The accepted JWE algorithms must not be null");
		}

		if (!supportedAlgorithms().containsAll(acceptedAlgs)) {
			throw new IllegalArgumentException("Unsupported JWE algorithm(s)");
		}

		if (!compatibleAlgorithms().containsAll(acceptedAlgs)) {
			throw new IllegalArgumentException("JWE algorithm(s) not compatible with key size");
		}

		this.acceptedAlgs = acceptedAlgs;
	}


	@Override
	public Set<EncryptionMethod> getAcceptedEncryptionMethods() {

		return acceptedEncs;
	}


	@Override
	public void setAcceptedEncryptionMethods(final Set<EncryptionMethod> acceptedEncs) {

		if (acceptedEncs == null)
			throw new IllegalArgumentException("The accepted encryption methods must not be null");

		if (!supportedEncryptionMethods().containsAll(acceptedEncs)) {
			throw new IllegalArgumentException("Unsupported encryption method(s)");
		}

		this.acceptedEncs = acceptedEncs;
	}


	@Override
	public Set<String> getIgnoredCriticalHeaderParameters() {

		return critParamChecker.getIgnoredCriticalHeaders();
	}


	@Override
	public void setIgnoredCriticalHeaderParameters(final Set<String> headers) {

		critParamChecker.setIgnoredCriticalHeaders(headers);
	}


	@Override
	public byte[] decrypt(final JWEHeader header,
			      final Base64URL encryptedKey,
			      final Base64URL iv,
			      final Base64URL cipherText,
			      final Base64URL authTag)
		throws JOSEException {

		// Validate required JWE parts
		if (encryptedKey == null) {

			throw new JOSEException("The encrypted key must not be null");
		}

		if (iv == null) {

			throw new JOSEException("The initialization vector (IV) must not be null");
		}

		if (authTag == null) {

			throw new JOSEException("The authentication tag must not be null");
		}

		if (!critParamChecker.headerPasses(header)) {

			throw new JOSEException("Unsupported critical header parameter");
		}


		// Derive the content encryption key
		JWEAlgorithm alg = header.getAlgorithm();
		int keyLength = header.getEncryptionMethod().cekBitLength();

		SecretKey cek;

		if (alg.equals(JWEAlgorithm.A128KW) ||
		    alg.equals(JWEAlgorithm.A192KW) ||
		    alg.equals(JWEAlgorithm.A256KW))   {

			cek = AESKW.decryptCEK(kek, encryptedKey.decode());

		} else if (alg.equals(JWEAlgorithm.A128GCMKW) ||
			   alg.equals(JWEAlgorithm.A192GCMKW) ||
			   alg.equals(JWEAlgorithm.A256GCMKW)) {

			byte[] keyIV = header.getIV().decode();
			byte[] keyTag = header.getAuthenticationTag().decode();
			AuthenticatedCipherText authEncrCEK = new AuthenticatedCipherText(encryptedKey.decode(), keyTag);
			cek = AESGCMKW.decryptCEK(kek, keyIV, authEncrCEK, keyLength, keyEncryptionProvider);

		} else {

			throw new JOSEException("Unsupported JWE algorithm, must be A128KW, A192KW, A256KW, A128GCMKW, A192GCMKW orA256GCMKW");
		}

		// Compose the AAD
		byte[] aad = StringUtils.toByteArray(header.toBase64URL().toString());

		// Decrypt the cipher text according to the JWE enc
		EncryptionMethod enc = header.getEncryptionMethod();

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
				contentEncryptionProvider,
				macProvider);

		} else if (enc.equals(EncryptionMethod.A128GCM) ||
			enc.equals(EncryptionMethod.A192GCM) ||
			enc.equals(EncryptionMethod.A256GCM)) {

			plainText = AESGCM.decrypt(
				cek,
				iv.decode(),
				cipherText.decode(),
				aad,
				authTag.decode(),
				contentEncryptionProvider);

		} else if (enc.equals(EncryptionMethod.A128CBC_HS256_DEPRECATED) ||
			enc.equals(EncryptionMethod.A256CBC_HS512_DEPRECATED)) {

			plainText = AESCBC.decryptWithConcatKDF(
				header,
				cek,
				encryptedKey,
				iv,
				cipherText,
				authTag,
				contentEncryptionProvider,
				macProvider);

		} else {

			throw new JOSEException("Unsupported encryption method, must be A128CBC_HS256, A192CBC_HS384, A256CBC_HS512, A128GCM, A192GCM or A256GCM");
		}


		// Apply decompression if requested
		return DeflateHelper.applyDecompression(header, plainText);
	}
}