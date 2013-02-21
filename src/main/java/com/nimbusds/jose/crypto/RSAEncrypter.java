package com.nimbusds.jose.crypto;


import com.nimbusds.jose.*;

import com.nimbusds.jose.util.Base64URL;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;

import javax.crypto.*;

import javax.crypto.spec.IvParameterSpec;

import java.math.BigInteger;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;


/**
 * RSA encrypter.
 *
 * @author David Ortiz
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-02-21)
 */
public class RSAEncrypter extends RSAProvider implements JWEEncrypter {


	/**
	 * Random byte generator.
	 */
	private final SecureRandom randomGen;


	/**
	 * The public RSA key.
	 */
	private final RSAPublicKey pubKey;


	/**
	 * Creates a new RSA encrypter.
	 *
	 * @param pubKey The public RSA key. Must not be {@code null}.
	 */
	public RSAEncrypter(final RSAPublicKey pubKey) {
		
		this.pubKey = pubKey;

		try {
			randomGen = SecureRandom.getInstance("SHA1PRNG");

		} catch(NoSuchAlgorithmException e) {

			 throw new ProviderException("Java Security provider doesn't support SHA1PRNG");
		}
	}


	@Override
	public JWECryptoParts encrypt(ReadOnlyJWEHeader readOnlyJWEHeader, byte[] bytes)
		throws JOSEException {

		// The alg parameter
		JWEAlgorithm algorithm = readOnlyJWEHeader.getAlgorithm();

		// The enc parameter
		EncryptionMethod method = readOnlyJWEHeader.getEncryptionMethod();
		
		// The second JWE part
		Base64URL encryptedKey = null;

		// The fourth JWE part
		Base64URL cipherText = null;


		try {
			final int keyLength = keyLengthForMethod(method);

			SecretKey contentEncryptionKey = generateAESCMK(keyLength);

			if (algorithm.equals(JWEAlgorithm.RSA1_5)) {

				Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
				cipher.init(Cipher.ENCRYPT_MODE, pubKey);
				encryptedKey = Base64URL.encode(cipher.doFinal(contentEncryptionKey.getEncoded()));

			} else if (algorithm.equals(JWEAlgorithm.RSA_OAEP)) {

				try {
					AsymmetricBlockCipher engine = new RSAEngine();

					// JCA identifier RSA/ECB/OAEPWithSHA-1AndMGF1Padding ?
					OAEPEncoding cipher = new OAEPEncoding(engine);

					BigInteger mod = pubKey.getModulus();
					BigInteger exp = pubKey.getPublicExponent();
					RSAKeyParameters keyParams = new RSAKeyParameters(false, mod, exp);
					cipher.init(true, keyParams);

					int inputBlockSize = cipher.getInputBlockSize();
					int outputBlockSize = cipher.getOutputBlockSize();

					byte[] keyBytes = contentEncryptionKey.getEncoded();

					encryptedKey = Base64URL.encode(cipher.processBlock(keyBytes, 0, keyBytes.length));

				} catch (InvalidCipherTextException e) {

					throw new JOSEException(e.getMessage(), e);
				}

			} else {
				throw new JOSEException("Algorithm must be RSA1_5 or RSA_OAEP");
			}


			if (encryptedKey == null )
				throw new JOSEException("Couldn't generate encrypted key");


			JWECryptoParts parts;

			if (method.equals(EncryptionMethod.A128GCM) || method.equals(EncryptionMethod.A256GCM)) {

				byte[] iv = generateAESGCMIV();

				IvParameterSpec ivParamSpec = new IvParameterSpec(iv);
				cipherText = Base64URL.encode(aesgcmEncrypt(ivParamSpec, contentEncryptionKey, bytes));
				parts = new JWECryptoParts(encryptedKey,  Base64URL.encode(iv), cipherText , null);
				return parts;

			}
			else{
				throw new JOSEException("Unsupported encryption method");
			}


		} catch (InvalidKeyException e) {
			throw new JOSEException("Invalid Key Exception", e);
		} catch (NoSuchAlgorithmException e) {
			throw new JOSEException("Java Security Provider doesn't support the algorithm specified", e);

		} catch (BadPaddingException e) {
			throw new JOSEException("Bad padding exception", e);
		} catch (NoSuchPaddingException e) {
			throw new JOSEException("No such padding Exception", e);
		} catch (IllegalBlockSizeException e) {
			throw new JOSEException("Illegal Block Size exception", e);
		}
	}


	/**
	 * Generates an AES Content Master Key (CMK) of the specified length.
	 *
	 * @param keyLength The key length, in bits.
	 *
	 * @return The AES CMK.
	 *
	 * @throws NoSuchAlgorithmException If AES key generation is not
	 *                                  supported.
	 */
	protected static SecretKey generateAESCMK(final int keyLength) 
		throws NoSuchAlgorithmException {

		KeyGenerator keygen;
		keygen = KeyGenerator.getInstance("AES");
		keygen.init(keyLength);
		return keygen.generateKey();
	}


	/**
	 * Generates a random 96 bit (12 byte) Initialisation Vector(IV) for
	 * use in AES-GCM encryption.
	 *
	 * <p>See http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-08#section-4.9
	 *
	 * @return The random 96 bit IV.
	 */
	protected byte[] generateAESGCMIV() {
		
		byte[] bytes = new byte[12];

		randomGen.nextBytes(bytes);

		return bytes;
	}
}