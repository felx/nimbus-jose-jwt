package com.nimbusds.jose.crypto;


import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;

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
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A128GCM}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A256GCM}
 * </ul>
 *
 * @author David Ortiz
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-03-22)
 */
public class RSAEncrypter extends RSACryptoProvider implements JWEEncrypter {


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
	 *
	 * @throws JOSEException If the underlying secure random generator
	 *                       couldn't be instantiated.
	 */
	public RSAEncrypter(final RSAPublicKey pubKey)
		throws JOSEException {

		this.pubKey = pubKey;

		try {
			randomGen = SecureRandom.getInstance("SHA1PRNG");

		} catch(NoSuchAlgorithmException e) {

			throw new JOSEException(e.getMessage(), e);
		}
	}


	@Override
	public JWECryptoParts encrypt(final ReadOnlyJWEHeader readOnlyJWEHeader, final byte[] bytes)
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
			final int keyLength = RSACryptoProvider.keyLengthForMethod(method);

			SecretKey contentEncryptionKey = AES.generateAESCMK(keyLength);

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


			if (encryptedKey == null ) {
				throw new JOSEException("Couldn't generate encrypted key");
			}


			JWECryptoParts parts;

			if (method.equals(EncryptionMethod.A128GCM) || method.equals(EncryptionMethod.A256GCM)) {

				byte[] iv = AESGCM.generateIV(randomGen);

				String authDataString = readOnlyJWEHeader.toBase64URL().toString() + "." +
				                        encryptedKey.toString() + "." +
				                        Base64URL.encode(iv).toString();


				byte[] authData = authDataString.getBytes("UTF-8");

				
				AESGCM.Result result = AESGCM.encrypt(contentEncryptionKey, bytes, authData, iv);

				parts = new JWECryptoParts(encryptedKey,  
					                   Base64URL.encode(iv), 
					                   Base64URL.encode(result.getCipherText()),
					                   Base64URL.encode(result.getAuthenticationTag()));
				return parts;
			}
			else{
				throw new JOSEException("Unsupported encryption method");
			}
		} catch (UnsupportedEncodingException e) {
			throw new JOSEException(e.getMessage(), e);

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
}