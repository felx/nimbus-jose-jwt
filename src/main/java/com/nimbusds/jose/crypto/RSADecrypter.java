package com.nimbusds.jose.crypto;


import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.util.Set;
import javax.crypto.SecretKey;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.StringUtils;


/**
 * RSA decrypter of {@link com.nimbusds.jose.JWEObject JWE objects}. This class
 * is thread-safe.
 *
 * <p>Supports the following JWE algorithms:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#RSA1_5}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#RSA_OAEP}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#RSA_OAEP_256}
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
 * @author David Ortiz
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-04-23)
 */
@ThreadSafe
public class RSADecrypter extends RSACryptoProvider implements JWEDecrypter, CriticalHeaderParamsAware {


	/**
	 * The critical header policy.
	 */
	private final CriticalHeaderParamsDeferral critPolicy = new CriticalHeaderParamsDeferral();


	/**
	 * The private RSA key.
	 */
	private final RSAPrivateKey privateKey;


	/**
	 * Creates a new RSA decrypter.
	 *
	 * @param privateKey The private RSA key. Must not be {@code null}.
	 */
	public RSADecrypter(final RSAPrivateKey privateKey) {

		this(privateKey, null);
	}


	/**
	 * Creates a new RSA decrypter.
	 *
	 * @param rsaJWK The RSA JSON Web Key (JWK). Must contain a private
	 *               part. Must not be {@code null}.
	 *
	 * @throws JOSEException If the RSA JWK doesn't contain a private part
	 *                       or its extraction failed.
	 */
	public RSADecrypter(final RSAKey rsaJWK)
		throws JOSEException {

		if (! rsaJWK.isPrivate()) {
			throw new JOSEException("The RSA JWK doesn't contain a private part");
		}

		privateKey = rsaJWK.toRSAPrivateKey();
	}


	/**
	 * Creates a new RSA decrypter.
	 *
	 * @param privateKey     The private RSA key. Must not be {@code null}.
	 * @param defCritHeaders The names of the critical header parameters
	 *                       that are deferred to the application for
	 *                       processing, empty set or {@code null} if none.
	 */
	public RSADecrypter(final RSAPrivateKey privateKey,
			    final Set<String> defCritHeaders) {

		if (privateKey == null) {
			throw new IllegalArgumentException("The private RSA key must not be null");
		}

		this.privateKey = privateKey;

		critPolicy.setDeferredCriticalHeaderParams(defCritHeaders);
	}


	/**
	 * Gets the private RSA key.
	 *
	 * @return The private RSA key.
	 */
	public RSAPrivateKey getPrivateKey() {

		return privateKey;
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

		// Validate required JWE parts
		if (encryptedKey == null) {
			throw new JOSEException("Missing JWE encrypted key");
		}	

		if (iv == null) {
			throw new JOSEException("Missing JWE initialization vector (IV)");
		}

		if (authTag == null) {
			throw new JOSEException("Missing JWE authentication tag");
		}

		if (! critPolicy.headerPasses(header)) {
			throw new JOSEException("Unsupported critical header parameter(s)");
		}
		

		// Derive the content encryption key
		JWEAlgorithm alg = header.getAlgorithm();

		SecretKey cek;

		if (alg.equals(JWEAlgorithm.RSA1_5)) {

			int keyLength = header.getEncryptionMethod().cekBitLength();

			// Protect against MMA attack by generating random CEK on failure,
			// see http://www.ietf.org/mail-archive/web/jose/current/msg01832.html
			SecureRandom randomGen = getJWEJCAProvider().getSecureRandom();
			SecretKey randomCEK = AES.generateKey(keyLength, randomGen);

			try {
				cek = RSA1_5.decryptCEK(privateKey, encryptedKey.decode(), keyLength, getJWEJCAProvider().getKeyEncryptionProvider());

				if (cek == null) {
					// CEK length mismatch, signalled by null instead of
					// exception to prevent MMA attack
					cek = randomCEK;
				}

			} catch (Exception e) {
				// continue
				cek = randomCEK;
			}
		
		} else if (alg.equals(JWEAlgorithm.RSA_OAEP)) {

			cek = RSA_OAEP.decryptCEK(privateKey, encryptedKey.decode(), getJWEJCAProvider().getKeyEncryptionProvider());

		} else if (alg.equals(JWEAlgorithm.RSA_OAEP_256)) {
			
			cek = RSA_OAEP_256.decryptCEK(privateKey, encryptedKey.decode(), getJWEJCAProvider().getKeyEncryptionProvider());
			
		} else {
		
			throw new JOSEException("Unsupported JWE algorithm, must be RSA1_5 or RSA_OAEP");
		}

		// Compose the AAD
		byte[] aad = StringUtils.toByteArray(header.toBase64URL().toString());

		// Decrypt the cipher text according to the JWE enc
		EncryptionMethod enc = header.getEncryptionMethod();

		byte[] plainText;

		if (enc.equals(EncryptionMethod.A128CBC_HS256) ||
		    enc.equals(EncryptionMethod.A192CBC_HS384) ||
		    enc.equals(EncryptionMethod.A256CBC_HS512)    ) {

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
			   enc.equals(EncryptionMethod.A256GCM)    ) {

			plainText = AESGCM.decrypt(
				cek,
				iv.decode(),
				cipherText.decode(),
				aad,
				authTag.decode(),
				getJWEJCAProvider().getContentEncryptionProvider());

		} else if (enc.equals(EncryptionMethod.A128CBC_HS256_DEPRECATED) ||
			   enc.equals(EncryptionMethod.A256CBC_HS512_DEPRECATED)    ) {

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

