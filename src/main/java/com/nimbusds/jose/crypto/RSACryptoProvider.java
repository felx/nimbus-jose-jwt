package com.nimbusds.jose.crypto;


import java.util.HashSet;
import java.util.Set;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
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
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A128CBC_HS256}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A256CBC_HS512}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A128GCM}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A256GCM}
 * </ul>
 * 
 * @author David Ortiz
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-03-25)
 */
abstract class RSACryptoProvider extends BaseJWEProvider {


	/**
	 * The supported JWE algorithms.
	 */
	public static final Set<JWEAlgorithm> SUPPORTED_ALGORITHMS;


	/**
	 * The supported encryption methods.
	 */
	public static final Set<EncryptionMethod> SUPPORTED_ENCRYPTION_METHODS;


	/**
	 * Initialises the supported algorithms and encryption methods.
	 */
	static {

		Set<JWEAlgorithm> algs = new HashSet<JWEAlgorithm>();
		algs.add(JWEAlgorithm.RSA1_5);
		algs.add(JWEAlgorithm.RSA_OAEP);
		SUPPORTED_ALGORITHMS = algs;

		Set<EncryptionMethod> methods = new HashSet<EncryptionMethod>();
		methods.add(EncryptionMethod.A128CBC_HS256);
		methods.add(EncryptionMethod.A256CBC_HS512);
		methods.add(EncryptionMethod.A128GCM);
		methods.add(EncryptionMethod.A256GCM);
		SUPPORTED_ENCRYPTION_METHODS = methods;
	}


	/**
	 * Gets the Content Master Key (CMK) length for the specified 
	 * encryption method.
	 *
	 * @param method The encryption method. Must be supported by this RSA
	 *               provider. Must not be {@code null}.
	 *
	 * @return The CMK length, in bits.
	 *
	 * @throws JOSEException If the encryption method is not supported.
	 */
	protected static int cmkBitLength(final EncryptionMethod method)
		throws JOSEException {

		if (method.equals(EncryptionMethod.A128CBC_HS256)) {

			return 256;

		} else if (method.equals(EncryptionMethod.A256CBC_HS512)) {

			return 512;

		} else if (method.equals(EncryptionMethod.A128GCM)) {

			return 128;

		} else if (method.equals(EncryptionMethod.A256GCM)) {
		        
		        return 256;

		} else {

			throw new JOSEException("Unsupported encryption method, must be A128CBC_HS256, A256CBC_HS512, A128GCM or A256GCM, ");
		}
	}


	/**
	 * Gets the Content Encryption Key (CEK) length for the specified 
	 * encryption method.
	 *
	 * @param method The encryption method. Must be supported by this RSA
	 *               provider and must employ CEKs. Must not be 
	 *               {@code null}.
	 *
	 * @return The CEK length, in bits.
	 *
	 * @throws JOSEException If the encryption method is not supported or
	 *                       doesn't employ CEKs.
	 */
	protected static int cekBitLength(final EncryptionMethod method)
		throws JOSEException {

		return cmkBitLength(method);
	}


	/**
	 * Gets the Content Integrity Key (CIK) length for the specified 
	 * encryption method.
	 *
	 * @param method The encryption method. Must be supported by this RSA
	 *               provider and must employ CIKs. Must not be 
	 *               {@code null}.
	 *
	 * @return The CIK length, in bits.
	 *
	 * @throws JOSEException If the encryption method is not supported or
	 *                       doesn't employ CIKs.
	 */
	protected static int cikBitLength(final EncryptionMethod method)
		throws JOSEException {

		if (method.equals(EncryptionMethod.A128CBC_HS256)) {

			return 256;

		} else if (method.equals(EncryptionMethod.A256CBC_HS512)) {

			return 512;

		} else {

			throw new JOSEException("Unsupported encryption method, must be A128CBC_HS256 or A256CBC_HS512");
		}
	}


	/**
	 * Creates a new RSA encryption / decryption provider.
	 */
	protected RSACryptoProvider() {

		super(SUPPORTED_ALGORITHMS, SUPPORTED_ENCRYPTION_METHODS);
	}
}
