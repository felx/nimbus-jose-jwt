package com.nimbusds.jose.crypto;


import java.util.HashSet;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.crypto.BlockCipher;

import org.bouncycastle.crypto.engines.AESEngine;

import org.bouncycastle.crypto.modes.GCMBlockCipher;

import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import org.bouncycastle.jce.provider.BouncyCastleProvider;


import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEAlgorithmProvider;


/**
 * The base abstract class for RSA encrypters and decrypters of
 * {@link com.nimbusds.jose.JWEObject JWE objects}.
 *
 * <p>Supports the following JSON Web Algorithms (JWAs):
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#RSA1_5}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#RSA_OAEP}
 * </ul>
 *
 * <p>Supports the following encryption methods:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A128GCM}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A256GCM}
 * </ul>
 * 
 * @author David Ortiz
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-02-22)
 */
abstract class RSAProvider implements JWEAlgorithmProvider {


	public static final Set<JWEAlgorithm> SUPPORTED_ALGORITHMS;


	public static final Set<EncryptionMethod> SUPPORTED_ENCRYPTION_METHODS;


	static {
		Set<JWEAlgorithm> algs = new HashSet<JWEAlgorithm>();
		algs.add(JWEAlgorithm.RSA_OAEP);
		algs.add(JWEAlgorithm.RSA1_5);
		SUPPORTED_ALGORITHMS = algs;

		Set<EncryptionMethod> methods = new HashSet<EncryptionMethod>();
		methods.add(EncryptionMethod.A256GCM);
		methods.add(EncryptionMethod.A128GCM);
		SUPPORTED_ENCRYPTION_METHODS = methods;
	}


	public Set<JWEAlgorithm> supportedAlgorithms() {
		return SUPPORTED_ALGORITHMS;
	}

	public Set<EncryptionMethod> supportedEncryptionMethods() {
		return SUPPORTED_ENCRYPTION_METHODS;
	}


	/**
	 * Gets the Content Master Key (CMK) length for the specified 
	 * encryption method.
	 *
	 * @param method The encryption method. Must be supported by this RSA
	 *               provider. Must not be {@code null}.
	 *
	 * @return The CMK length, in bits.
	 */
	protected int keyLengthForMethod(final EncryptionMethod method) {
		
		if (method.equals(EncryptionMethod.A128CBC_HS256) || 
		    method.equals(EncryptionMethod.A128GCM)) {

			return 128;
		}

		if (method.equals(EncryptionMethod.A256GCM) ||
		    method.equals(EncryptionMethod.A256CBC_HS512)) {
	
			return 256;
		}

		throw new IllegalArgumentException("Unsupported encryption method, must be A128GCM, A256GCM, A128CBC_HS256 or A256CBC_HS512");
	}


	protected byte[] aesgcmDecrypt(IvParameterSpec ivParamSpec, SecretKey secretKey, byte[] cipherText)
		throws JOSEException {

		return aesgcm(ivParamSpec, secretKey, cipherText, Cipher.DECRYPT_MODE);
	}


	protected byte[] aesgcmEncrypt(IvParameterSpec ivParamSpec, SecretKey secretKey, byte[] cipherText)
		throws JOSEException {
	
		return aesgcm(ivParamSpec, secretKey, cipherText, Cipher.ENCRYPT_MODE);
	}


	protected AEADParameters generateAEADParameters(final SecretKey secretKey, 
		                                        final byte[] authData) {

		final int authTagLength = 128;
		byte[] nonce = new byte[16];

		return new AEADParameters(new KeyParameter(secretKey.getEncoded()), authTagLength, nonce, authData);
	}


	protected AESGCMResult encryptAESGCM(final SecretKey secretKey, 
		                             final byte[] plainText, 
		                             final byte[] authData)
		throws Exception {


		AEADParameters aeadParams = generateAEADParameters(secretKey, authData);

		GCMBlockCipher gcm = new GCMBlockCipher(new AESEngine());

		gcm.init(true, aeadParams);

		int cipherTextLength = gcm.getOutputSize(plainText.length) - 128;


		// Produce cipher text
		byte[] cipherText = new byte[cipherTextLength];

		int outputCipherTextLength = gcm.processBytes(plainText, 0, plainText.length, cipherText, 0);

		if (outputCipherTextLength != cipherTextLength)
			throw new JOSEException("Unexpected output cipher text length");

		// Produce 128 bit authentication tag
		byte[] authTag = new byte[128];

		try {
			gcm.doFinal(authData, 0); // appends the AEAD data

		} catch (org.bouncycastle.crypto.InvalidCipherTextException e) {

			// TBD
		}

		return new AESGCMResult(cipherText, authTag);
	}


	private byte[] aesgcm(IvParameterSpec ivParamSpec, SecretKey secretKey, byte[] cipherText, int encryptMode) 
		throws JOSEException {


		try {
			Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", new BouncyCastleProvider());
			cipher.init(encryptMode, secretKey, ivParamSpec);
			return cipher.doFinal(cipherText);

		} catch (Exception e) {

			throw new JOSEException(e.getMessage());
		}
	}
}
