package com.nimbusds.jose.crypto;


import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.jwk.ECKey;


/**
 * The base abstract class for Elliptic Curve Diffie-Hellman encrypters and
 * decrypters of {@link com.nimbusds.jose.JWEObject JWE objects}.
 *
 * <p>Supports the following JSON Web Algorithms (JWAs):
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#ECDH_ES}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#ECDH_ES_A128KW}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#ECDH_ES_A192KW}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#ECDH_ES_A256KW}
 * </ul>
 *
 * <p>Supports the following JOSE Elliptic Curves:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.jwk.ECKey.Curve#P_256}
 *     <li>{@link com.nimbusds.jose.jwk.ECKey.Curve#P_384}
 *     <li>{@link com.nimbusds.jose.jwk.ECKey.Curve#P_521}
 * </ul>
 *
 * <p>Supports the following encryption methods:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A128CBC_HS256}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A192CBC_HS384}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A256CBC_HS512}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A128GCM}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A192GCM}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A256GCM}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A128CBC_HS256_DEPRECATED}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A256CBC_HS512_DEPRECATED}
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-05-26)
 */
abstract class ECDHCryptoProvider extends BaseJWEProvider {


	/**
	 * The supported JWE algorithms by the ECDH crypto provider class.
	 */
	public static final Set<JWEAlgorithm> SUPPORTED_ALGORITHMS;


	/**
	 * The supported encryption methods by the ECDH crypto provider class.
	 */
	public static final Set<EncryptionMethod> SUPPORTED_ENCRYPTION_METHODS = ContentCryptoProvider.SUPPORTED_ENCRYPTION_METHODS;


	/**
	 * The supported EC JWK curves by the ECDH crypto provider class.
	 */
	public static final Set<ECKey.Curve> SUPPORTED_EC;


	/**
	 * Initialises the supported algorithms and encryption methods.
	 */
	static {
		Set<JWEAlgorithm> algs = new LinkedHashSet<>();
		algs.add(JWEAlgorithm.ECDH_ES);
		algs.add(JWEAlgorithm.ECDH_ES_A128KW);
		algs.add(JWEAlgorithm.ECDH_ES_A192KW);
		algs.add(JWEAlgorithm.ECDH_ES_A256KW);
		SUPPORTED_ALGORITHMS = Collections.unmodifiableSet(algs);

		Set<ECKey.Curve> curves = new LinkedHashSet<>();
		curves.add(ECKey.Curve.P_256);
		curves.add(ECKey.Curve.P_384);
		curves.add(ECKey.Curve.P_521);
		SUPPORTED_EC = Collections.unmodifiableSet(curves);
	}


	/**
	 * The key curve.
	 */
	private final ECKey.Curve curve;


	/**
	 * The Concatenation Key Derivation Function (KDF).
	 */
	private final ConcatKDF concatKDF;


	/**
	 * Creates a new Elliptic Curve Diffie-Hellman encryption /decryption
	 * provider.
	 */
	protected ECDHCryptoProvider(final ECKey.Curve curve)
		throws JOSEException {

		super(SUPPORTED_ALGORITHMS, ContentCryptoProvider.SUPPORTED_ENCRYPTION_METHODS);

		ECKey.Curve definedCurve = curve != null ? curve : new ECKey.Curve("unknown");

		if (! SUPPORTED_EC.contains(curve)) {
			throw new JOSEException(AlgorithmSupportMessage.unsupportedEllipticCurve(
				definedCurve, SUPPORTED_EC));
		}

		this.curve = curve;

		concatKDF = new ConcatKDF("SHA-256");
	}


	/**
	 * Returns the Concatenation Key Derivation Function (KDF).
	 *
	 * @return The concat KDF.
	 */
	protected ConcatKDF getConcatKDF() {

		return concatKDF;
	}


	/**
	 * Returns the names of the supported elliptic curves. These correspond
	 * to the {@code crv} EC JWK parameter.
	 *
	 * @return The supported elliptic curves.
	 */
	public Set<ECKey.Curve> supportedEllipticCurves() {

		return SUPPORTED_EC;
	}


	/**
	 * Returns the elliptic curve of the key (using JWK designation).
	 *
	 * @return The curve.
	 */
	public ECKey.Curve getCurve() {

		return curve;
	}
}