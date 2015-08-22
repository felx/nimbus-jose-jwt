package com.nimbusds.jose.crypto.factories;


import java.security.Key;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;

import javax.crypto.SecretKey;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.proc.JWEDecrypterFactory;


/**
 * Default JSON Web Encryption (JWE) decrypter factory.
 *
 * <p>Supports all standard JWE algorithms implemented in the
 * {@link com.nimbusds.jose.crypto} package.
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-06-29
 */
@ThreadSafe
public class DefaultJWEDecrypterFactory implements JWEDecrypterFactory {


	@Override
	public JWEDecrypter createJWEDecrypter(final JWEHeader header, final Key key)
		throws JOSEException {

		if (RSADecrypter.SUPPORTED_ALGORITHMS.contains(header.getAlgorithm()) &&
			RSADecrypter.SUPPORTED_ENCRYPTION_METHODS.contains(header.getEncryptionMethod())) {

			if (!(key instanceof RSAPrivateKey)) {
				throw new KeyTypeException(RSAPrivateKey.class);
			}

			RSAPrivateKey rsaPrivateKey = (RSAPrivateKey)key;

			return new RSADecrypter(rsaPrivateKey);

		} else if (ECDHDecrypter.SUPPORTED_ALGORITHMS.contains(header.getAlgorithm()) &&
			ECDHDecrypter.SUPPORTED_ENCRYPTION_METHODS.contains(header.getEncryptionMethod())) {

			if (!(key instanceof ECPrivateKey)) {
				throw new KeyTypeException(ECPrivateKey.class);
			}

			ECPrivateKey ecPrivateKey = (ECPrivateKey)key;
			return new ECDHDecrypter(ecPrivateKey);

		} else if (DirectDecrypter.SUPPORTED_ALGORITHMS.contains(header.getAlgorithm()) &&
			DirectDecrypter.SUPPORTED_ENCRYPTION_METHODS.contains(header.getEncryptionMethod())) {

			if (!(key instanceof SecretKey)) {
				throw new KeyTypeException(SecretKey.class);
			}

			SecretKey aesKey = (SecretKey)key;
			DirectDecrypter directDecrypter =  new DirectDecrypter(aesKey);

			if (! directDecrypter.supportedEncryptionMethods().contains(header.getEncryptionMethod())) {
				throw new KeyLengthException(header.getEncryptionMethod().cekBitLength(), header.getEncryptionMethod());
			}

			return directDecrypter;

		} else if (AESDecrypter.SUPPORTED_ALGORITHMS.contains(header.getAlgorithm()) &&
			AESDecrypter.SUPPORTED_ENCRYPTION_METHODS.contains(header.getEncryptionMethod())) {

			if (!(key instanceof SecretKey)) {
				throw new KeyTypeException(SecretKey.class);
			}

			SecretKey aesKey = (SecretKey)key;
			AESDecrypter aesDecrypter = new AESDecrypter(aesKey);

			if (! aesDecrypter.supportedJWEAlgorithms().contains(header.getAlgorithm())) {
				throw new KeyLengthException(header.getAlgorithm());
			}

			return aesDecrypter;

		} else if (PasswordBasedDecrypter.SUPPORTED_ALGORITHMS.contains(header.getAlgorithm()) &&
			PasswordBasedDecrypter.SUPPORTED_ENCRYPTION_METHODS.contains(header.getEncryptionMethod())) {

			if (!(key instanceof SecretKey)) {
				throw new KeyTypeException(SecretKey.class);
			}

			byte[] password = key.getEncoded();
			return new PasswordBasedDecrypter(password);

		} else {

			throw new JOSEException("Unsupported JWE algorithm or encryption method");
		}
	}
}
