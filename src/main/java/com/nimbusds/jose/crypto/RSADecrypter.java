package com.nimbusds.jose.crypto;


import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.HashSet;
import java.util.Set;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.nimbusds.jose.DefaultJWEHeaderFilter;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEHeaderFilter;
import com.nimbusds.jose.ReadOnlyJWEHeader;
import com.nimbusds.jose.util.Base64URL;


/**
 * RSA decrypter of {@link com.nimbusds.jose.JWEObject JWE objects}. This class
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
 * <p>Accepts all {@link com.nimbusds.jose.JWEHeader#getReservedParameterNames
 * reserved JWE header parameters}. Modify the {@link #getJWEHeaderFilter
 * header filter} properties to restrict the acceptable JWE algorithms, 
 * encryption methods and header parameters, or to allow custom JWE header 
 * parameters.
 * 
 * @author David Ortiz
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-03-22)
 *
 */
public class RSADecrypter extends RSACryptoProvider implements JWEDecrypter {


	/**
	 * The JWE header filter.
	 */
	private final DefaultJWEHeaderFilter headerFilter;


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

		headerFilter = new DefaultJWEHeaderFilter(supportedAlgorithms(), supportedEncryptionMethods());
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
	public JWEHeaderFilter getJWEHeaderFilter() {

		return headerFilter;
	}


	@Override
	public byte[] decrypt(final ReadOnlyJWEHeader readOnlyJWEHeader,
		              final Base64URL encryptedKey,
		              final Base64URL iv,
		              final Base64URL cipherText,
		              final Base64URL integrityValue) 
		throws JOSEException {


		// Validate required JWE parts
		if (encryptedKey == null) {

			throw new JOSEException("The encrypted key must not be null");
		}	

		if (iv == null) {

			throw new JOSEException("The initialization vector (IV) must not be null");
		}

		if (integrityValue == null) {

			throw new JOSEException("The integrity value must not be null");
		}
		

		// Derive the encryption AES key
		SecretKeySpec keySpec = getKeySpec(readOnlyJWEHeader.getAlgorithm(), 
			                           readOnlyJWEHeader.getEncryptionMethod(), 
			                           encryptedKey.decode(), 
			                           privateKey);

		// Compose the authenticated data (AEAD)
		String authDataString = readOnlyJWEHeader.toBase64URL().toString() + "." +
					encryptedKey.toString() + "." +
					iv.toString();
		
		byte[] authData = null;

		try {
			authData = authDataString.getBytes("UTF-8");

		} catch (UnsupportedEncodingException e) {

			throw new JOSEException(e.getMessage(), e);
		}

		return AESGCM.decrypt(keySpec, cipherText.decode(), authData, integrityValue.decode(), iv.decode());
	}


	/**
	 * Obtains the AES key.
	 *
	 * @param alg        The JWE algorithm. Must not be {@code null}.
	 * @param method     The encryption method. Must not be {@code null}.
	 * @param cipherText The cipher text. Must not be {@code null}.
	 * @param inputKey   The private RSA key. Must not be {@code null}.
	 *
	 * @return The AES key.
	 *
	 * @throws JOSEException If the AES key couldn't be obtained.
	 */
	private SecretKeySpec getKeySpec(final JWEAlgorithm alg, 
		                         final EncryptionMethod method, 
		                         final byte[] cipherText,
		                         final PrivateKey inputKey) 
		throws JOSEException {

		int keyLength = keyLengthForMethod(method);


		try {
			if (alg.equals(JWEAlgorithm.RSA_OAEP)) {

				RSAPrivateKey key = (RSAPrivateKey) inputKey;
				RSAEngine engine = new RSAEngine();
				OAEPEncoding cipher = new OAEPEncoding(engine);
				BigInteger mod = key.getModulus();
				BigInteger exp = key.getPrivateExponent();
				RSAKeyParameters keyParams = new RSAKeyParameters(true, mod, exp);
				cipher.init(false, keyParams);
				byte[] secretKeyBytes = cipher.processBlock(cipherText, 0, cipherText.length);
				return new SecretKeySpec(secretKeyBytes, "AES");

			} else if (alg.equals(JWEAlgorithm.RSA1_5)) {
		
				Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
				cipher.init(Cipher.DECRYPT_MODE, privateKey);
				byte[] secretKeyBytes = cipher.doFinal(cipherText);

				if (8 * secretKeyBytes.length != keyLength) {

					throw new JOSEException("WebToken.decrypt RSA PKCS1Padding symmetric key length mismatch: " + 
						                secretKeyBytes.length + " != " + keyLength);
				}

				return new SecretKeySpec(secretKeyBytes, "AES");

	    		} else {
		
				throw new JOSEException("Unsupported JWEAlgorithm");
	    		}

	    	} catch (JOSEException e) {

	    		throw e;

		} catch (Exception e) {

			throw new JOSEException(e.getMessage(), e);
		}
	}
}

