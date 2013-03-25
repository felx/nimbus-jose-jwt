package com.nimbusds.jose.crypto;


import java.io.UnsupportedEncodingException;
import java.security.interfaces.RSAPrivateKey;
import java.util.Set;

import javax.crypto.SecretKey;

import org.bouncycastle.util.Arrays;

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
 * @version $version$ (2013-03-25)
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
		JWEAlgorithm alg = readOnlyJWEHeader.getAlgorithm();

		SecretKey cmk = null;

		if (alg.equals(JWEAlgorithm.RSA1_5)) {

			int keyLength = cmkBitLength(readOnlyJWEHeader.getEncryptionMethod());

			cmk = RSA1_5.decryptCMK(privateKey, encryptedKey.decode(), keyLength);
		
		} else if (alg.equals(JWEAlgorithm.RSA_OAEP)) {

			cmk = RSA_OAEP.decryptCMK(privateKey, encryptedKey.decode());

		} else {
		
			throw new JOSEException("Unsupported algorithm, must be RSA1_5 or RSA_OAEP");
	    	}

	    	EncryptionMethod enc = readOnlyJWEHeader.getEncryptionMethod();

	    	if (enc.equals(EncryptionMethod.A128CBC_HS256) || enc.equals(EncryptionMethod.A256CBC_HS512)    ) {

	    		byte[] epu = null;

			if (readOnlyJWEHeader.getEncryptionPartyUInfo() != null) {

				epu = readOnlyJWEHeader.getEncryptionPartyUInfo().decode();
			}

			byte[] epv = null;
			
			if (readOnlyJWEHeader.getEncryptionPartyVInfo() != null) {

				epv = readOnlyJWEHeader.getEncryptionPartyVInfo().decode();
			}

	    		SecretKey cek = ConcatKDF.generateCEK(cmk, enc, epu, epv);

			byte[] clearText = AESCBC.decrypt(cek, iv.decode(), cipherText.decode());

			SecretKey cik = ConcatKDF.generateCIK(cmk, enc, epu, epv);

			String macInput = readOnlyJWEHeader.toBase64URL().toString() + "." +
			                  encryptedKey.toString() + "." +
			                  iv.toString() + "." +
			                  cipherText.toString();

			byte[] mac = HMAC.compute(cik, macInput.getBytes());

			if (! Arrays.constantTimeAreEqual(integrityValue.decode(), mac)) {

				throw new JOSEException("HMAC integrity check failed");
			}

	    		return clearText;

	    	} else if (enc.equals(EncryptionMethod.A128GCM) || enc.equals(EncryptionMethod.A256GCM)    ) {

	    		// Compose the additional authenticated data
			String authDataString = readOnlyJWEHeader.toBase64URL().toString() + "." +
						encryptedKey.toString() + "." +
						iv.toString();

			byte[] authData = null;

			try {
				authData = authDataString.getBytes("UTF-8");

			} catch (UnsupportedEncodingException e) {

				throw new JOSEException(e.getMessage(), e);
			}

			return AESGCM.decrypt(cmk, iv.decode(), cipherText.decode(), authData, integrityValue.decode());

	    	} else {

	    		throw new JOSEException("Unsupported encryption method, must be A128CBC_HS256, A256CBC_HS512, A128GCM or A128GCM");
	    	}
	}
}

