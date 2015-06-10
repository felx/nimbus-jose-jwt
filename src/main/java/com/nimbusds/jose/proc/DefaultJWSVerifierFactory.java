package com.nimbusds.jose.proc;


import java.security.Key;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.SecretKey;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;


/**
 * Default JSON Web Signature (JWS) verifier factory.
 *
 * <p>Supports all standard JWS algorithms implemented in the
 * {@link com.nimbusds.jose.crypto} package.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-06-08)
 */
@ThreadSafe
public class DefaultJWSVerifierFactory implements JWSVerifierFactory {


	@Override
	public JWSVerifier createJWSVerifier(final JWSHeader header, final Key key)
		throws JOSEException {

		if (MACVerifier.SUPPORTED_ALGORITHMS.contains(header.getAlgorithm())) {

			if (!(key instanceof SecretKey)) {
				throw new KeyTypeException(SecretKey.class);
			}

			SecretKey macKey = (SecretKey)key;

			return new MACVerifier(macKey);

		} else if (RSASSAVerifier.SUPPORTED_ALGORITHMS.contains(header.getAlgorithm())) {

			if (!(key instanceof RSAPublicKey)) {
				throw new KeyTypeException(RSAPublicKey.class);
			}

			RSAPublicKey rsaPublicKey = (RSAPublicKey)key;

			return new RSASSAVerifier(rsaPublicKey);

		} else if (ECDSAVerifier.SUPPORTED_ALGORITHMS.contains(header.getAlgorithm())) {

			if (!(key instanceof ECPublicKey)) {
				throw new KeyTypeException(ECPublicKey.class);
			}

			ECPublicKey ecPublicKey = (ECPublicKey)key;

			return new ECDSAVerifier(ecPublicKey);

		} else {

			throw new JOSEException("Unsupported JWS algorithm");
		}
	}
}
