package com.nimbusds.jose.crypto;

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

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEHeaderFilter;
import com.nimbusds.jose.ReadOnlyJWEHeader;
import com.nimbusds.jose.util.Base64URL;


public class RSADecrypter extends RSAProvider implements JWEDecrypter {
	private final String symmetricAlgorithm = "AES";


	public static final JWEHeaderFilter HEADER_FILTER = new JWEHeaderFilter() {


		@Override
		public Set<JWEAlgorithm> getAcceptedAlgorithms() {
			return SUPPORTED_ALGORITHMS;
		}

		@Override
		public void setAcceptedAlgorithms(Set<JWEAlgorithm> jweAlgorithms) {
		}

		@Override
		public Set<EncryptionMethod> getAcceptedEncryptionMethods() {
			return SUPPORTED_ENCRYPTION_METHODS;
		}

		@Override
		public void setAcceptedEncryptionMethods(Set<EncryptionMethod> encryptionMethods) {
		}

		@Override
		public Set<String> getAcceptedParameters() {
			Set<String> parameters = new HashSet<String>();
			parameters.add("alg");
			parameters.add("enc");
			parameters.add("zip");
			parameters.add("typ");


			return parameters;
		}
	};

	private RSAPrivateKey privateKey;



	@Override
	public JWEHeaderFilter getJWEHeaderFilter() {
		return HEADER_FILTER;
	}

	public RSADecrypter(RSAPrivateKey privateKey){
		this.privateKey = privateKey;
	}

	@Override
	public byte[] decrypt(final ReadOnlyJWEHeader readOnlyJWEHeader,
			final Base64URL encryptedKey,
			final Base64URL iv,
			final Base64URL cipherText,
			final Base64URL integrityValue) throws JOSEException {


		JWEAlgorithm algorithm = readOnlyJWEHeader.getAlgorithm();
		EncryptionMethod method = readOnlyJWEHeader.getEncryptionMethod();
		int keyLength = this.keyLengthForMethod(method);
		SecretKeySpec keySpec;


		keySpec = getKeySpec(algorithm, method, encryptedKey.decode(), privateKey);
		if (iv == null) {
			throw new JOSEException("Missing initialization vector \"iv\" header");
		}

		byte[] ivBytes = iv.decode();
		IvParameterSpec ivParamSpec = new IvParameterSpec(ivBytes);

		try {
			Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", new BouncyCastleProvider());
			cipher.init(Cipher.DECRYPT_MODE, keySpec, ivParamSpec);
			return cipher.doFinal(cipherText.decode());
		} catch (NoSuchAlgorithmException e) {
			throw new JOSEException(e.getMessage(), e);
		} catch (NoSuchPaddingException e) {
			throw new JOSEException(e.getMessage(), e);
		} catch (IllegalBlockSizeException e) {
			throw new JOSEException(e.getMessage(), e);
		} catch (BadPaddingException e) {
			throw new JOSEException(e.getMessage(), e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new JOSEException(e.getMessage(), e);
		} catch (InvalidKeyException e) {
			throw new JOSEException(e.getMessage(), e);
		}


	}

	private SecretKeySpec getKeySpec(final JWEAlgorithm alg, final EncryptionMethod method, final byte[] cipherText,
			final PrivateKey inputKey) throws JOSEException {
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
				return new SecretKeySpec(secretKeyBytes, symmetricAlgorithm );

			} else if (alg.equals(JWEAlgorithm.RSA1_5)) {
				Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
				cipher.init(Cipher.DECRYPT_MODE, privateKey);
				byte[] secretKeyBytes = cipher.doFinal(cipherText);

				if (8 * secretKeyBytes.length != keyLength) {
					throw new Exception("WebToken.decrypt RSA PKCS1Padding symmetric key length mismatch: " + secretKeyBytes.length + " != " + keyLength);
				}

				return new SecretKeySpec(secretKeyBytes, symmetricAlgorithm);

			} else {
				throw new JOSEException("Unsupported JWEAlgorithm");
			}
		} catch (InvalidCipherTextException e) {
			throw new JOSEException(e.getMessage(), e);
		} catch (IllegalBlockSizeException e) {
			throw new JOSEException(e.getMessage(), e);
		} catch (BadPaddingException e) {
			throw new JOSEException(e.getMessage(), e);
		} catch (NoSuchAlgorithmException e) {
			throw new JOSEException(e.getMessage(), e);
		} catch (NoSuchPaddingException e) {
			throw new JOSEException(e.getMessage(), e);
		} catch (Exception e) {
			throw new JOSEException(e.getMessage(), e);
		}


	}
}
