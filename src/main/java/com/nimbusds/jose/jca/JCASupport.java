package com.nimbusds.jose.jca;


import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;


/**
 * Java Cryptography Architecture (JCA) support helper.
 */
public class JCASupport {


	/**
	 * Checks if the specified JWS algorithm is supported by the default
	 * system JCA provider(s).
	 *
	 * @param alg The JWS algorithm. Must not be {@code null}.
	 *
	 * @return {@code true} if the JWS algorithm is supported, else
	 *         {@code false}.
	 */
	public static boolean isSupported(final JWSAlgorithm alg) {

		for (Provider p: Security.getProviders()) {

			if (isSupported(alg, p)) {
				return true;
			}
		}

		return false;
	}


	/**
	 * Checks if a JWS algorithm is supported by the the specified JCA
	 * provider.
	 *
	 * @param alg      The JWS algorithm. Must not be {@code null}.
	 * @param provider The JCA provider. Must not be {@code null}.
	 *
	 * @return {@code true} if the JWS algorithm is supported, else
	 *         {@code false}.
	 */
	public static boolean isSupported(final JWSAlgorithm alg, final Provider provider) {

		if (JWSAlgorithm.Family.HMAC_SHA.contains(alg)) {
			String jcaName;
			if (alg.equals(JWSAlgorithm.HS256)) {
				jcaName = "HMACSHA256";
			} else if (alg.equals(JWSAlgorithm.HS384)) {
				jcaName = "HMACSHA384";
			} else if (alg.equals(JWSAlgorithm.HS512)) {
				jcaName = "HMACSHA512";
			} else {
				return false;
			}
			return provider.getService("KeyGenerator", jcaName) != null;
		}

		if (JWSAlgorithm.Family.RSA.contains(alg)) {
			String jcaName;
			if (alg.equals(JWSAlgorithm.RS256)) {
				jcaName = "SHA256withRSA";
			} else if (alg.equals(JWSAlgorithm.RS384)) {
				jcaName = "SHA384withRSA";
			} else if (alg.equals(JWSAlgorithm.RS512)) {
				jcaName = "SHA512withRSA";
			} else if (alg.equals(JWSAlgorithm.PS256)) {
				jcaName = "SHA256withRSAandMGF1";
			} else if (alg.equals(JWSAlgorithm.PS384)) {
				jcaName = "SHA384withRSAandMGF1";
			} else if (alg.equals(JWSAlgorithm.PS512)) {
				jcaName = "SHA512withRSAandMGF1";
			} else {
				return false;
			}
			return provider.getService("Signature", jcaName) != null;
		}

		if (JWSAlgorithm.Family.EC.contains(alg)) {
			String jcaName;
			if (alg.equals(JWSAlgorithm.ES256)) {
				jcaName = "SHA256withECDSA";
			} else if (alg.equals(JWSAlgorithm.ES384)) {
				jcaName = "SHA384withECDSA";
			} else if (alg.equals(JWSAlgorithm.ES512)) {
				jcaName = "SHA512withECDSA";
			} else {
				return false;
			}
			return provider.getService("Signature", jcaName) != null;
		}

		return false;
	}


	/**
	 * Checks if the specified JWE algorithm is supported by the default
	 * system JCA provider(s).
	 *
	 * @param alg The JWE algorithm. Must not be {@code null}.
	 *
	 * @return {@code true} if the JWE algorithm is supported, else
	 *         {@code false}.
	 */
	public static boolean isSupported(final JWEAlgorithm alg) {

		for (Provider p: Security.getProviders()) {

			if (isSupported(alg, p)) {
				return true;
			}
		}

		return false;
	}


	/**
	 * Checks if a JWE algorithm is supported by the the specified JCA
	 * provider.
	 *
	 * @param alg      The JWE algorithm. Must not be {@code null}.
	 * @param provider The JCA provider. Must not be {@code null}.
	 *
	 * @return {@code true} if the JWE algorithm is supported, else
	 *         {@code false}.
	 */
	public static boolean isSupported(final JWEAlgorithm alg, final Provider provider) {

		String jcaName;

		if (JWEAlgorithm.Family.RSA.contains(alg)) {
			if (alg.equals(JWEAlgorithm.RSA1_5)) {
				jcaName = "RSA/ECB/PKCS1Padding";
			} else if (alg.equals(JWEAlgorithm.RSA_OAEP)) {
				jcaName = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding";
			} else if (alg.equals(JWEAlgorithm.RSA_OAEP_256)) {
				jcaName = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
			} else {
				return false;
			}

			// Do direct test
			try {
				Cipher.getInstance(jcaName, provider);
			} catch (NoSuchAlgorithmException e) {
				return false;
			} catch (NoSuchPaddingException e) {
				return false;
			}
			return true;
		}

		if (JWEAlgorithm.Family.AES_KW.contains(alg)) {
			return provider.getService("Cipher", "AESWrap") != null;
		}

		if (JWEAlgorithm.Family.ECDH_ES.contains(alg)) {
			return provider.getService("KeyAgreement", "ECDH") != null;
		}

		if (JWEAlgorithm.Family.AES_GCM_KW.contains(alg)) {
			// Do direct test
			try {
				Cipher.getInstance("AES/GCM/NoPadding", provider);
			} catch (NoSuchAlgorithmException e) {
				return false;
			} catch (NoSuchPaddingException e) {
				return false;
			}
			return true;
		}

		if (JWEAlgorithm.Family.PBES2.contains(alg)) {
			String hmac;
			if (alg.equals(JWEAlgorithm.PBES2_HS256_A128KW)) {
				hmac = "HmacSHA256";
			} else if (alg.equals(JWEAlgorithm.PBES2_HS384_A192KW)) {
				hmac = "HmacSHA384";
			} else {
				hmac = "HmacSHA512";
			}
			return provider.getService("KeyGenerator", hmac) != null;
		}

		return false;
	}


	/**
	 * Checks if the specified JWE encryption method is supported by the
	 * default system JCA provider(s).
	 *
	 * @param enc The JWE encryption method. Must not be {@code null}.
	 *
	 * @return {@code true} if the JWE algorithm is supported, else
	 *         {@code false}.
	 */
	public static boolean isSupported(final EncryptionMethod enc) {

		for (Provider p: Security.getProviders()) {

			if (isSupported(enc, p)) {
				return true;
			}
		}

		return false;
	}


	/**
	 * Checks if a JWE encryption method is supported by the specified
	 * JCA provider.
	 *
	 * @param enc      The JWE encryption method. Must not be {@code null}.
	 * @param provider The JCA provider. Must not be {@code null}.
	 *
	 * @return {@code true} if the JWE encryption method is supported, else
	 *         {@code false}.
	 */
	public static boolean isSupported(final EncryptionMethod enc, final Provider provider) {

		if (EncryptionMethod.Family.AES_CBC_HMAC_SHA.contains(enc)) {
			// Do direct test
			try {
				Cipher.getInstance("AES/CBC/PKCS5Padding", provider);
			} catch (NoSuchAlgorithmException e) {
				return false;
			} catch (NoSuchPaddingException e) {
				return false;
			}
			// Check hmac
			String hmac;
			if (enc.equals(EncryptionMethod.A128CBC_HS256)) {
				hmac = "HmacSHA256";
			} else if (enc.equals(EncryptionMethod.A192CBC_HS384)) {
				hmac = "HmacSHA384";
			} else {
				hmac = "HmacSHA512";
			}
			return provider.getService("KeyGenerator", hmac) != null;
		}

		if (EncryptionMethod.Family.AES_GCM.contains(enc)) {
			// Do direct test
			try {
				Cipher.getInstance("AES/GCM/NoPadding", provider);
			} catch (NoSuchAlgorithmException e) {
				return false;
			} catch (NoSuchPaddingException e) {
				return false;
			}
			return true;
		}

		return false;
	}
}
