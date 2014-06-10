package com.nimbusds.jose.crypto;


import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.util.HashSet;
import java.util.Set;

import javax.crypto.SecretKey;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.ReadOnlyJWEHeader;
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
 * <p>Accepts all {@link com.nimbusds.jose.JWEHeader#getRegisteredParameterNames
 * registered JWE header parameters}. Use {@link #setAcceptedAlgorithms} and
 * {@link #setAcceptedEncryptionMethods} to restrict the acceptable JWE
 * algorithms and encryption methods.
 * 
 * @author David Ortiz
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-05-23)
 *
 */
public class RSADecrypter extends RSACryptoProvider implements JWEDecrypter {


	/**
	 * The accepted JWE algorithms.
	 */
	private Set<JWEAlgorithm> acceptedAlgs =
		new HashSet<JWEAlgorithm>(supportedAlgorithms());


	/**
	 * The accepted encryption methods.
	 */
	private Set<EncryptionMethod> acceptedEncs =
		new HashSet<EncryptionMethod>(supportedEncryptionMethods());


	/**
	 * The critical header parameter checker.
	 */
	private final CriticalHeaderParameterChecker critParamChecker =
		new CriticalHeaderParameterChecker();


	/**
	 * The private RSA key.
	 */
	private RSAPrivateKey privateKey;


	/**
	 * Creates a new RSA decrypter.
	 *
	 * @param privateKey The private RSA key. Must not be {@code null}.
	 */
	public RSADecrypter(final RSAPrivateKey privateKey) {

		if (privateKey == null) {

			throw new IllegalArgumentException("The private RSA key must not be null");
		}

		this.privateKey = privateKey;
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
	public Set<JWEAlgorithm> getAcceptedAlgorithms() {

		return acceptedAlgs;
	}


	@Override
	public void setAcceptedAlgorithms(final Set<JWEAlgorithm> acceptedAlgs) {

		if (acceptedAlgs == null) {
			throw new IllegalArgumentException("The accepted JWE algorithms must not be null");
		}

		if (! supportedAlgorithms().containsAll(acceptedAlgs)) {
			throw new IllegalArgumentException("Unsupported JWE algorithm(s)");
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
	public byte[] decrypt(final ReadOnlyJWEHeader header,
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

		if (! critParamChecker.headerPasses(header)) {

			throw new JOSEException("Unsupported critical header parameter");
		}
		

		// Derive the content encryption key
		JWEAlgorithm alg = header.getAlgorithm();

		SecretKey cek;

		if (alg.equals(JWEAlgorithm.RSA1_5)) {

			int keyLength = header.getEncryptionMethod().cekBitLength();

			// Protect against MMA attack by generating random CEK on failure,
			// see http://www.ietf.org/mail-archive/web/jose/current/msg01832.html
			SecureRandom randomGen = getSecureRandom();
			SecretKey randomCEK = AES.generateKey(keyLength, randomGen);

			try {
				cek = RSA1_5.decryptCEK(privateKey, encryptedKey.decode(), keyLength, keyEncryptionProvider);

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

			cek = RSA_OAEP.decryptCEK(privateKey, encryptedKey.decode(), keyEncryptionProvider);

		} else if (alg.equals(JWEAlgorithm.RSA_OAEP_256)) {
			
			cek = RSA_OAEP_256.decryptCEK(privateKey, encryptedKey.decode(), keyEncryptionProvider);
			
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
				contentEncryptionProvider,
				macProvider);

		} else if (enc.equals(EncryptionMethod.A128GCM) ||
			   enc.equals(EncryptionMethod.A192GCM) ||
			   enc.equals(EncryptionMethod.A256GCM)    ) {

			plainText = AESGCM.decrypt(
				cek,
				iv.decode(),
				cipherText.decode(),
				aad,
				authTag.decode(),
				contentEncryptionProvider);

		} else if (enc.equals(EncryptionMethod.A128CBC_HS256_DEPRECATED) ||
			   enc.equals(EncryptionMethod.A256CBC_HS512_DEPRECATED)    ) {

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

