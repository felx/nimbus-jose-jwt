package com.nimbusds.jose.crypto;


import java.security.interfaces.RSAPrivateKey;

import javax.crypto.SecretKey;

import com.nimbusds.jose.DefaultJWEHeaderFilter;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEHeaderFilter;
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
 * <p>Accepts all {@link com.nimbusds.jose.JWEHeader#getReservedParameterNames
 * reserved JWE header parameters}. Modify the {@link #getJWEHeaderFilter
 * header filter} properties to restrict the acceptable JWE algorithms, 
 * encryption methods and header parameters, or to allow custom JWE header 
 * parameters.
 * 
 * @author David Ortiz
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-05-06)
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
		

		// Derive the content encryption key
		JWEAlgorithm alg = readOnlyJWEHeader.getAlgorithm();

		SecretKey cek = null;

		if (alg.equals(JWEAlgorithm.RSA1_5)) {

			int keyLength = readOnlyJWEHeader.getEncryptionMethod().cekBitLength();

			SecretKey randomCEK = AES.generateKey(keyLength);

			try {
				cek = RSA1_5.decryptCEK(privateKey, encryptedKey.decode(), keyLength);	
			
			} catch (Exception e) {

				// Protect against MMA attack by generating random CEK on failure, 
				// see http://www.ietf.org/mail-archive/web/jose/current/msg01832.html
				cek = randomCEK;
			}
		
		} else if (alg.equals(JWEAlgorithm.RSA_OAEP)) {

			cek = RSA_OAEP.decryptCEK(privateKey, encryptedKey.decode());

		} else {
		
			throw new JOSEException("Unsupported JWE algorithm, must be RSA1_5 or RSA_OAEP");
	    	}

	    	EncryptionMethod enc = readOnlyJWEHeader.getEncryptionMethod();

	    	byte[] plainText;

		if (enc.equals(EncryptionMethod.A128CBC_HS256) || enc.equals(EncryptionMethod.A256CBC_HS512)) {

			byte[] aad = StringUtils.toByteArray(readOnlyJWEHeader.toBase64URL() + "." + encryptedKey);

			plainText = AESCBC.decryptAuthenticated(cek, iv.decode(), cipherText.decode(), aad, authTag.decode());

		} else if (enc.equals(EncryptionMethod.A128GCM) || enc.equals(EncryptionMethod.A256GCM)) {

			byte[] aad = StringUtils.toByteArray(readOnlyJWEHeader.toBase64URL() + "." + encryptedKey + "." + iv);

			plainText = AESGCM.decrypt(cek, iv.decode(), cipherText.decode(), aad, authTag.decode());

		} else {

			throw new JOSEException("Unsupported encryption method, must be A128CBC_HS256, A256CBC_HS512, A128GCM or A128GCM");
		}


	    	// Apply decompression if requested
	    	return DeflateHelper.applyDecompression(readOnlyJWEHeader, plainText);
	}
}

