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


/**
 * RSA decrypter.
 * 
 * @author David Ortiz
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-03-22)
 *
 */
public class RSADecrypter extends RSACryptoProvider implements JWEDecrypter {


	private final String symmetricAlgorithm = "AES";


    public static final JWEHeaderFilter HEADER_FILTER = new JWEHeaderFilter() {


	public Set<JWEAlgorithm> getAcceptedAlgorithms() {
	    return SUPPORTED_ALGORITHMS;
	}

	public void setAcceptedAlgorithms(Set<JWEAlgorithm> jweAlgorithms) {
	}

	public Set<EncryptionMethod> getAcceptedEncryptionMethods() {
	    return SUPPORTED_ENCRYPTION_METHODS;
	}

	public void setAcceptedEncryptionMethods(Set<EncryptionMethod> encryptionMethods) {
	}

	public Set<String> getAcceptedParameters() {
	    Set<String> parameters = new HashSet<String>();
	    parameters.add("alg");
	    parameters.add("enc");
	    parameters.add("zip");
	    parameters.add("typ");


	    return parameters;
	}


	public void setAcceptedParameters(final Set<String> parameters) {

		// ignore
	}
    };

    private RSAPrivateKey privateKey;



    public JWEHeaderFilter getJWEHeaderFilter() {
	return HEADER_FILTER;
    }

    public RSADecrypter(RSAPrivateKey privateKey){
	this.privateKey = privateKey;
    }

	public byte[] decrypt(final ReadOnlyJWEHeader readOnlyJWEHeader,
		              final Base64URL encryptedKey,
		              final Base64URL iv,
		              final Base64URL cipherText,
		              final Base64URL integrityValue) 
		throws JOSEException {


	if (encryptedKey == null)
		throw new JOSEException("Missing encrypted key");

	if (iv == null)
		throw new JOSEException("Missing initialization vector");

	if (integrityValue == null)
		throw new JOSEException("Missing integrity value");


	JWEAlgorithm algorithm = readOnlyJWEHeader.getAlgorithm();
	EncryptionMethod method = readOnlyJWEHeader.getEncryptionMethod();
	int keyLength = this.keyLengthForMethod(method);
	SecretKeySpec keySpec;


	keySpec = getKeySpec(algorithm, method, encryptedKey.decode(), privateKey);


	String authDataString = readOnlyJWEHeader.toBase64URL().toString() + "." +
				encryptedKey.toString() + "." +
				iv.toString();


	byte[] authData = null;

	try {
		authData = authDataString.getBytes("UTF-8");
	
	} catch (Exception e) {

		throw new JOSEException(e.getMessage(), e);
	}

	return AESGCM.decrypt(keySpec, cipherText.decode(), authData, integrityValue.decode(), iv.decode());

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

