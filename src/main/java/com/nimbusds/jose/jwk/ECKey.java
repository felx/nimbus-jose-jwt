package com.nimbusds.jose.jwk;


import java.math.BigInteger;
import java.net.URI;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.util.List;
import java.util.LinkedHashMap;
import java.util.Set;

import net.jcip.annotations.Immutable;

import net.minidev.json.JSONObject;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.util.*;


/**
 * Public and private {@link KeyType#EC Elliptic Curve} JSON Web Key (JWK). 
 * Uses the BouncyCastle.org provider for EC key import and export. This class
 * is immutable.
 *
 * <p>Example JSON object representation of a public EC JWK:
 * 
 * <pre>
 * {
 *   "kty" : "EC",
 *   "crv" : "P-256",
 *   "x"   : "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
 *   "y"   : "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
 *   "use" : "enc",
 *   "kid" : "1"
 * }
 * </pre>
 *
 * <p>Example JSON object representation of a public and private EC JWK:
 *
 * <pre>
 * {
 *   "kty" : "EC",
 *   "crv" : "P-256",
 *   "x"   : "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
 *   "y"   : "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
 *   "d"   : "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
 *   "use" : "enc",
 *   "kid" : "1"
 * }
 * </pre>
 *
 * <p>See http://en.wikipedia.org/wiki/Elliptic_curve_cryptography
 *
 * @author Vladimir Dzhuvinov
 * @author Justin Richer
 * @version 2015-09-28
 */
@Immutable
public final class ECKey extends JWK {


	/**
	 * Cryptographic curve. This class is immutable.
	 *
	 * <p>Includes constants for the following standard cryptographic 
	 * curves:
	 *
	 * <ul>
	 *     <li>{@link #P_256}
	 *     <li>{@link #P_384}
	 *     <li>{@link #P_521}
	 * </ul>
	 *
	 * <p>See "Digital Signature Standard (DSS)", FIPS PUB 186-3, June 
	 * 2009, National Institute of Standards and Technology (NIST).
	 */
	@Immutable
	public static class Curve {


		/**
		 * P-256 curve (secp256r1, also called prime256v1).
		 */
		public static final Curve P_256 = new Curve("P-256", "secp256r1");


		/**
		 * P-384 curve (secp384r1).
		 */
		public static final Curve P_384 = new Curve("P-384", "secp384r1");


		/**
		 * P-521 curve (secp521r1).
		 */
		public static final Curve P_521 = new Curve("P-521", "secp521r1");


		/**
		 * The JOSE curve name.
		 */
		private final String name;


		/**
		 * The standard curve name, {@code null} if not specified.
		 */
		private final String stdName;


		/**
		 * Creates a new cryptographic curve with the specified JOSE
		 * name. A standard curve name is not unspecified.
		 *
		 * @param name The JOSE name of the cryptographic curve. Must not be
		 *             {@code null}.
		 */
		public Curve(final String name) {

			this(name, null);
		}


		/**
		 * Creates a new cryptographic curve with the specified JOSE
		 * and standard names.
		 *
		 * @param name    The JOSE name of the cryptographic curve. 
		 *                Must not be {@code null}.
		 * @param stdName The standard name of the cryptographic curve,
		 *                {@code null} if not specified.
		 */
		public Curve(final String name, final String stdName) {

			if (name == null) {
				throw new IllegalArgumentException("The JOSE cryptographic curve name must not be null");
			}

			this.name = name;

			this.stdName = stdName;
		}


		/**
		 * Returns the JOSE name of this cryptographic curve.
		 *
		 * @return The JOSE name.
		 */
		public String getName() {

			return name;
		}


		/**
		 * Returns the standard name of this cryptographic curve.
		 *
		 * @return The standard name, {@code null} if not specified.
		 */
		public String getStdName() {

			return stdName;
		}


		/**
		 * Returns the parameter specification for this cryptographic
		 * curve.
		 *
		 * @return The EC parameter specification, {@code null} if it
		 *         cannot be determined.
		 */
		public ECParameterSpec toECParameterSpec() {

			return ECParameterTable.get(this);
		}


		/**
		 * @see #getName
		 */
		@Override
		public String toString() {

			return getName();
		}


		@Override
		public boolean equals(final Object object) {

			return object instanceof Curve &&
			       this.toString().equals(object.toString());
		}


		/**
		 * Parses a cryptographic curve from the specified string.
		 *
		 * @param s The string to parse. Must not be {@code null} or
		 *          empty.
		 *
		 * @return The cryptographic curve.
		 */
		public static Curve parse(final String s) {

			if (s == null || s.trim().isEmpty()) {
				throw new IllegalArgumentException("The cryptographic curve string must not be null or empty");
			}

			if (s.equals(P_256.getName())) {
				return P_256;

			} else if (s.equals(P_384.getName())) {
				return P_384;

			} else if (s.equals(P_521.getName())) {
				return P_521;

			} else {
				return new Curve(s);
			}
		}


		/**
		 * Gets the cryptographic curve for the specified standard
		 * name.
		 *
		 * @param stdName The standard curve name. May be {@code null}.
		 *
		 * @return The curve, {@code null} if it cannot be determined.
		 */
		public static Curve forStdName(final String stdName) {
			if( "secp256r1".equals(stdName) || "prime256v1".equals(stdName)) {
				 return P_256;
			} else if( "secp384r1".equals(stdName) ) {
				return P_384;
			} else if( "secp521r1".equals(stdName) ) {
				return P_521;
			} else {
				return null;
			}
		}


		/**
		 * Gets the cryptographic curve for the specified parameter
		 * specification.
		 *
		 * @param spec The EC parameter spec. May be {@code null}.
		 *
		 * @return The curve, {@code null} if it cannot be determined.
		 */
		public static Curve forECParameterSpec(final ECParameterSpec spec) {

			return ECParameterTable.get(spec);
		}
	}


	/**
	 * Builder for constructing Elliptic Curve JWKs.
	 *
	 * <p>Example usage:
	 *
	 * <pre>
	 * ECKey key = new ECKey.Builder(Curve.P521, x, y).
	 *             d(d).
	 *             algorithm(JWSAlgorithm.ES512).
	 *             keyID("789").
	 *             build();
	 * </pre>
	 */
	public static class Builder {


		/**
		 * The curve name.
		 */
		private final Curve crv;


		/**
		 * The public 'x' EC coordinate.
		 */
		private final Base64URL x;


		/**
		 * The public 'y' EC coordinate.
		 */
		private final Base64URL y;
		

		/**
		 * The private 'd' EC coordinate, optional.
		 */
		private Base64URL d;


		/**
		 * The key use, optional.
		 */
		private KeyUse use;


		/**
		 * The key operations, optional.
		 */
		private Set<KeyOperation> ops;


		/**
		 * The intended JOSE algorithm for the key, optional.
		 */
		private Algorithm alg;


		/**
		 * The key ID, optional.
		 */
		private String kid;


		/**
		 * X.509 certificate URL, optional.
		 */
		private URI x5u;


		/**
		 * X.509 certificate thumbprint, optional.
		 */
		private Base64URL x5t;


		/**
		 * The X.509 certificate chain, optional.
		 */
		private List<Base64> x5c;


		/**
		 * Creates a new Elliptic Curve JWK builder.
		 *
		 * @param crv The cryptographic curve. Must not be 
		 *            {@code null}.
		 * @param x   The public 'x' coordinate for the elliptic curve 
		 *            point. It is represented as the Base64URL 
		 *            encoding of the coordinate's big endian 
		 *            representation. Must not be {@code null}.
		 * @param y   The public 'y' coordinate for the elliptic curve 
		 *            point. It is represented as the Base64URL 
		 *            encoding of the coordinate's big endian 
		 *            representation. Must not be {@code null}.
		 */
		public Builder(final Curve crv, final Base64URL x, final Base64URL y) {

			if (crv == null) {
				throw new IllegalArgumentException("The curve must not be null");
			}

			this.crv = crv;

			if (x == null) {
				throw new IllegalArgumentException("The 'x' coordinate must not be null");
			}

			this.x = x;

			if (y == null) {
				throw new IllegalArgumentException("The 'y' coordinate must not be null");
			}

			this.y = y;
		}


		/**
		 * Creates a new Elliptic Curve JWK builder.
		 *
		 * @param crv The cryptographic curve. Must not be 
		 *            {@code null}.
		 * @param pub The public EC key to represent. Must not be 
		 *            {@code null}.
		 */
		public Builder(final Curve crv, final ECPublicKey pub) {

			this(crv,
			     encodeCoordinate(pub.getParams().getCurve().getField().getFieldSize(), pub.getW().getAffineX()),
			     encodeCoordinate(pub.getParams().getCurve().getField().getFieldSize(), pub.getW().getAffineY()));
		}


		/**
		 * Sets the private 'd' coordinate for the elliptic curve 
		 * point. The alternative method is {@link #privateKey}.
		 *
		 * @param d The 'd' coordinate. It is represented as the 
		 *          Base64URL encoding of the coordinate's big endian 
		 *          representation. {@code null} if not specified (for
		 *          a public key).
		 *
		 * @return This builder.
		 */
		public Builder d(final Base64URL d) {

			this.d = d;
			return this;
		}


		/**
		 * Sets the private Elliptic Curve key. The alternative method 
		 * is {@link #d}.
		 *
		 * @param priv The private EC key, used to obtain the private
		 *             'd' coordinate for the elliptic curve point.
		 *             {@code null} if not specified (for a public 
		 *             key).
		 *
		 * @return This builder.
		 */
		public Builder privateKey(final ECPrivateKey priv) {

			if (priv != null) {
				this.d = encodeCoordinate(priv.getParams().getCurve().getField().getFieldSize(), priv.getS());
			}
			
			return this;
		}


		/**
		 * Sets the use ({@code use}) of the JWK.
		 *
		 * @param use The key use, {@code null} if not specified or if 
		 *            the key is intended for signing as well as 
		 *            encryption.
		 *
		 * @return This builder.
		 */
		public Builder keyUse(final KeyUse use) {

			this.use = use;
			return this;
		}


		/**
		 * Sets the operations ({@code key_ops}) of the JWK.
		 *
		 * @param ops The key operations, {@code null} if not
		 *            specified.
		 *
		 * @return This builder.
		 */
		public Builder keyOperations(final Set<KeyOperation> ops) {

			this.ops = ops;
			return this;
		}


		/**
		 * Sets the intended JOSE algorithm ({@code alg}) for the JWK.
		 *
		 * @param alg The intended JOSE algorithm, {@code null} if not 
		 *            specified.
		 *
		 * @return This builder.
		 */
		public Builder algorithm(final Algorithm alg) {

			this.alg = alg;
			return this;
		}

		/**
		 * Sets the ID ({@code kid}) of the JWK. The key ID can be used 
		 * to match a specific key. This can be used, for instance, to 
		 * choose a key within a {@link JWKSet} during key rollover. 
		 * The key ID may also correspond to a JWS/JWE {@code kid} 
		 * header parameter value.
		 *
		 * @param kid The key ID, {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder keyID(final String kid) {

			this.kid = kid;
			return this;
		}


		/**
		 * Sets the ID ({@code kid}) of the JWK to its SHA-256 JWK
		 * thumbprint (RFC 7638). The key ID can be used to match a
		 * specific key. This can be used, for instance, to choose a
		 * key within a {@link JWKSet} during key rollover. The key ID
		 * may also correspond to a JWS/JWE {@code kid} header
		 * parameter value.
		 *
		 * @return This builder.
		 *
		 * @throws JOSEException If the SHA-256 hash algorithm is not
		 *                       supported.
		 */
		public Builder keyIDFromThumbprint()
			throws JOSEException {

			return keyIDFromThumbprint("SHA-256");
		}


		/**
		 * Sets the ID ({@code kid}) of the JWK to its JWK thumbprint
		 * (RFC 7638). The key ID can be used to match a specific key.
		 * This can be used, for instance, to choose a key within a
		 * {@link JWKSet} during key rollover. The key ID may also
		 * correspond to a JWS/JWE {@code kid} header parameter value.
		 *
		 * @param hashAlg The hash algorithm for the JWK thumbprint
		 *                computation. Must not be {@code null}.
		 *
		 * @return This builder.
		 *
		 * @throws JOSEException If the hash algorithm is not
		 *                       supported.
		 */
		public Builder keyIDFromThumbprint(final String hashAlg)
			throws JOSEException {

			// Put mandatory params in sorted order
			LinkedHashMap<String,String> requiredParams = new LinkedHashMap<>();
			requiredParams.put("crv", crv.toString());
			requiredParams.put("kty", KeyType.EC.getValue());
			requiredParams.put("x", x.toString());
			requiredParams.put("y", y.toString());
			this.kid = ThumbprintUtils.compute(hashAlg, requiredParams).toString();
			return this;
		}


		/**
		 * Sets the X.509 certificate URL ({@code x5u}) of the JWK.
		 *
		 * @param x5u The X.509 certificate URL, {@code null} if not 
		 *            specified.
		 *
		 * @return This builder.
		 */
		public Builder x509CertURL(final URI x5u) {

			this.x5u = x5u;
			return this;
		}


		/**
		 * Sets the X.509 certificate thumbprint ({@code x5t}) of the
		 * JWK.
		 *
		 * @param x5t The X.509 certificate thumbprint, {@code null} if 
		 *            not specified.
		 *
		 * @return This builder.
		 */
		public Builder x509CertThumbprint(final Base64URL x5t) {

			this.x5t = x5t;
			return this;
		}


		/**
		 * Sets the X.509 certificate chain ({@code x5c}) of the JWK.
		 *
		 * @param x5c The X.509 certificate chain as a unmodifiable 
		 *            list, {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder x509CertChain(final List<Base64> x5c) {

			this.x5c = x5c;
			return this;
		}


		/**
		 * Builds a new octet sequence JWK.
		 *
		 * @return The octet sequence JWK.
		 *
		 * @throws IllegalStateException If the JWK parameters were
		 *                               inconsistently specified.
		 */
		public ECKey build() {

			try {
				if (d == null) {
					// Public key
					return new ECKey(crv, x, y, use, ops, alg, kid, x5u, x5t, x5c);
				}

				// Pair
				return new ECKey(crv, x, y, d, use, ops, alg, kid, x5u, x5t, x5c);

			} catch (IllegalArgumentException e) {

				throw new IllegalStateException(e.getMessage(), e);
			}
		}
	}


	/**
	 * Returns the Base64URL encoding of the specified elliptic curve 'x',
	 * 'y' or 'd' coordinate, with leading zero padding up to the specified
	 * field size in bits.
	 *
	 * @param fieldSize  The field size in bits.
	 * @param coordinate The elliptic curve coordinate. Must not be
	 *                   {@code null}.
	 *
	 * @return The Base64URL-encoded coordinate, with leading zero padding
	 *         up to the curve's field size.
	 */
	public static Base64URL encodeCoordinate(final int fieldSize, final BigInteger coordinate) {

		byte[] unpadded = BigIntegerUtils.toBytesUnsigned(coordinate);

		int bytesToOutput = (fieldSize + 7)/8;

		if (unpadded.length >= bytesToOutput) {
			// Greater-than check to prevent exception on malformed
			// key below
			return Base64URL.encode(unpadded);
		}

		byte[] padded = new byte[bytesToOutput];

		System.arraycopy(unpadded, 0, padded, bytesToOutput - unpadded.length, unpadded.length);

		return Base64URL.encode(padded);
	}


	/**
	 * The curve name.
	 */
	private final Curve crv;


	/**
	 * The public 'x' EC coordinate.
	 */
	private final Base64URL x;


	/**
	 * The public 'y' EC coordinate.
	 */
	private final Base64URL y;
	

	/**
	 * The private 'd' EC coordinate
	 */
	private final Base64URL d;


	/**
	 * Creates a new public Elliptic Curve JSON Web Key (JWK) with the 
	 * specified parameters.
	 *
	 * @param crv The cryptographic curve. Must not be {@code null}.
	 * @param x   The public 'x' coordinate for the elliptic curve point.
	 *            It is represented as the Base64URL encoding of the 
	 *            coordinate's big endian representation. Must not be 
	 *            {@code null}.
	 * @param y   The public 'y' coordinate for the elliptic curve point. 
	 *            It is represented as the Base64URL encoding of the 
	 *            coordinate's big endian representation. Must not be 
	 *            {@code null}.
	 * @param use The key use, {@code null} if not specified or if the key
	 *            is intended for signing as well as encryption.
	 * @param ops The key operations, {@code null} if not specified.
	 * @param alg The intended JOSE algorithm for the key, {@code null} if
	 *            not specified.
	 * @param kid The key ID, {@code null} if not specified.
	 * @param x5u The X.509 certificate URL, {@code null} if not specified.
	 * @param x5t The X.509 certificate thumbprint, {@code null} if not
	 *            specified.
	 * @param x5c The X.509 certificate chain, {@code null} if not 
	 *            specified.
	 */
	public ECKey(final Curve crv, final Base64URL x, final Base64URL y, 
		     final KeyUse use, final Set<KeyOperation> ops, final Algorithm alg, final String kid,
		     final URI x5u, final Base64URL x5t, final List<Base64> x5c) {

		super(KeyType.EC, use, ops, alg, kid, x5u, x5t, x5c);

		if (crv == null) {
			throw new IllegalArgumentException("The curve must not be null");
		}

		this.crv = crv;

		if (x == null) {
			throw new IllegalArgumentException("The 'x' coordinate must not be null");
		}

		this.x = x;

		if (y == null) {
			throw new IllegalArgumentException("The 'y' coordinate must not be null");
		}

		this.y = y;

		this.d = null;
	}


	/**
	 * Creates a new public / private Elliptic Curve JSON Web Key (JWK) 
	 * with the specified parameters.
	 *
	 * @param crv The cryptographic curve. Must not be {@code null}.
	 * @param x   The public 'x' coordinate for the elliptic curve point.
	 *            It is represented as the Base64URL encoding of the 
	 *            coordinate's big endian representation. Must not be 
	 *            {@code null}.
	 * @param y   The public 'y' coordinate for the elliptic curve point. 
	 *            It is represented as the Base64URL encoding of the 
	 *            coordinate's big endian representation. Must not be 
	 *            {@code null}.
	 * @param d   The private 'd' coordinate for the elliptic curve point. 
	 *            It is represented as the Base64URL encoding of the 
	 *            coordinate's big endian representation. Must not be 
	 *            {@code null}.
	 * @param use The key use, {@code null} if not specified or if the key
	 *            is intended for signing as well as encryption.
	 * @param ops The key operations, {@code null} if not specified.
	 * @param alg The intended JOSE algorithm for the key, {@code null} if
	 *            not specified.
	 * @param kid The key ID, {@code null} if not specified.
	 * @param x5u The X.509 certificate URL, {@code null} if not specified.
	 * @param x5t The X.509 certificate thumbprint, {@code null} if not
	 *            specified.
	 * @param x5c The X.509 certificate chain, {@code null} if not 
	 *            specified.
	 */
	public ECKey(final Curve crv, final Base64URL x, final Base64URL y, final Base64URL d,
		     final KeyUse use, final Set<KeyOperation> ops, final Algorithm alg, final String kid,
		     final URI x5u, final Base64URL x5t, final List<Base64> x5c) {

		super(KeyType.EC, use, ops, alg, kid, x5u, x5t, x5c);

		if (crv == null) {
			throw new IllegalArgumentException("The curve must not be null");
		}

		this.crv = crv;

		if (x == null) {
			throw new IllegalArgumentException("The 'x' coordinate must not be null");
		}

		this.x = x;

		if (y == null) {
			throw new IllegalArgumentException("The 'y' coordinate must not be null");
		}

		this.y = y;
		
		if (d == null) {
			throw new IllegalArgumentException("The 'd' coordinate must not be null");
		}

		this.d = d;
	}


	/**
	 * Creates a new public Elliptic Curve JSON Web Key (JWK) with the 
	 * specified parameters.
	 *
	 * @param crv The cryptographic curve. Must not be {@code null}.
	 * @param pub The public EC key to represent. Must not be {@code null}.
	 * @param use The key use, {@code null} if not specified or if the key
	 *            is intended for signing as well as encryption.
	 * @param ops The key operations, {@code null} if not specified.
	 * @param alg The intended JOSE algorithm for the key, {@code null} if
	 *            not specified.
	 * @param kid The key ID, {@code null} if not specified.
	 * @param x5u The X.509 certificate URL, {@code null} if not specified.
	 * @param x5t The X.509 certificate thumbprint, {@code null} if not
	 *            specified.
	 * @param x5c The X.509 certificate chain, {@code null} if not 
	 *            specified.
	 */
	public ECKey(final Curve crv, final ECPublicKey pub, 
		     final KeyUse use, final Set<KeyOperation> ops, final Algorithm alg, final String kid,
		     final URI x5u, final Base64URL x5t, final List<Base64> x5c) {

		this(crv, 
		     encodeCoordinate(pub.getParams().getCurve().getField().getFieldSize(), pub.getW().getAffineX()),
		     encodeCoordinate(pub.getParams().getCurve().getField().getFieldSize(), pub.getW().getAffineY()),
		     use, ops, alg, kid,
		     x5u, x5t, x5c);
	}


	/**
	 * Creates a new public / private Elliptic Curve JSON Web Key (JWK) 
	 * with the specified parameters.
	 *
	 * @param crv  The cryptographic curve. Must not be {@code null}.
	 * @param pub  The public EC key to represent. Must not be 
	 *             {@code null}.
	 * @param priv The private EC key to represent. Must not be 
	 *             {@code null}.
	 * @param use  The key use, {@code null} if not specified or if the key
	 *             is intended for signing as well as encryption.
	 * @param ops  The key operations, {@code null} if not specified.
	 * @param alg  The intended JOSE algorithm for the key, {@code null} if
	 *             not specified.
	 * @param kid  The key ID, {@code null} if not specified.
	 * @param x5u  The X.509 certificate URL, {@code null} if not 
	 *             specified.
	 * @param x5t  The X.509 certificate thumbprint, {@code null} if not
	 *             specified.
	 * @param x5c  The X.509 certificate chain, {@code null} if not 
	 *             specified.
	 */
	public ECKey(final Curve crv, final ECPublicKey pub, final ECPrivateKey priv, 
		     final KeyUse use, final Set<KeyOperation> ops, final Algorithm alg, final String kid,
		     final URI x5u, final Base64URL x5t, final List<Base64> x5c) {

		this(crv,
		     encodeCoordinate(pub.getParams().getCurve().getField().getFieldSize(), pub.getW().getAffineX()),
		     encodeCoordinate(pub.getParams().getCurve().getField().getFieldSize(), pub.getW().getAffineY()),
		     encodeCoordinate(priv.getParams().getCurve().getField().getFieldSize(), priv.getS()),
		     use, ops, alg, kid,
		     x5u, x5t, x5c);
	}


	/**
	 * Gets the cryptographic curve.
	 *
	 * @return The cryptographic curve.
	 */
	public Curve getCurve() {

		return crv;
	}


	/**
	 * Gets the public 'x' coordinate for the elliptic curve point.
	 *
	 * @return The 'x' coordinate. It is represented as the Base64URL 
	 *         encoding of the coordinate's big endian representation.
	 */
	public Base64URL getX() {

		return x;
	}


	/**
	 * Gets the public 'y' coordinate for the elliptic curve point.
	 *
	 * @return The 'y' coordinate. It is represented as the Base64URL 
	 *         encoding of the coordinate's big endian representation.
	 */
	public Base64URL getY() {

		return y;
	}

	
	/**
	 * Gets the private 'd' coordinate for the elliptic curve point. It is 
	 * represented as the Base64URL encoding of the coordinate's big endian 
	 * representation.
	 *
	 * @return The 'd' coordinate.  It is represented as the Base64URL 
	 *         encoding of the coordinate's big endian representation. 
	 *         {@code null} if not specified (for a public key).
	 */
	public Base64URL getD() {

		return d;
	}


	/**
	 * Returns a standard {@code java.security.interfaces.ECPublicKey} 
	 * representation of this Elliptic Curve JWK. Uses the default JCA
	 * provider.
	 * 
	 * @return The public Elliptic Curve key.
	 * 
	 * @throws JOSEException If EC is not supported by the underlying Java
	 *                       Cryptography (JCA) provider or if the JWK
	 *                       parameters are invalid for a public EC key.
	 */
	public ECPublicKey toECPublicKey()
		throws JOSEException {

		return toECPublicKey(null);
	}


	/**
	 * Returns a standard {@code java.security.interfaces.ECPublicKey}
	 * representation of this Elliptic Curve JWK.
	 *
	 * @param provider The specific JCA provider to use, {@code null}
	 *                 implies the default one.
	 *
	 * @return The public Elliptic Curve key.
	 *
	 * @throws JOSEException If EC is not supported by the underlying Java
	 *                       Cryptography (JCA) provider or if the JWK
	 *                       parameters are invalid for a public EC key.
	 */
	public ECPublicKey toECPublicKey(final Provider provider)
		throws JOSEException {

		ECParameterSpec spec = crv.toECParameterSpec();

		if (spec == null) {
			throw new JOSEException("Couldn't get EC parameter spec for curve " + crv);
		}

		ECPoint w = new ECPoint(x.decodeToBigInteger(), y.decodeToBigInteger());

		ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(w, spec);

		try {
			KeyFactory keyFactory;

			if (provider == null) {
				keyFactory = KeyFactory.getInstance("EC");
			} else {
				keyFactory = KeyFactory.getInstance("EC", provider);
			}

			return (ECPublicKey) keyFactory.generatePublic(publicKeySpec);

		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {

			throw new JOSEException(e.getMessage(), e);
		}
	}
	

	/**
	 * Returns a standard {@code java.security.interfaces.ECPrivateKey} 
	 * representation of this Elliptic Curve JWK. Uses the default JCA
	 * provider.
	 * 
	 * @return The private Elliptic Curve key, {@code null} if not 
	 *         specified by this JWK.
	 * 
	 * @throws JOSEException If EC is not supported by the underlying Java
	 *                       Cryptography (JCA) provider or if the JWK
	 *                       parameters are invalid for a private EC key.
	 */
	public ECPrivateKey toECPrivateKey()
		throws JOSEException {

		return toECPrivateKey(null);
	}


	/**
	 * Returns a standard {@code java.security.interfaces.ECPrivateKey}
	 * representation of this Elliptic Curve JWK.
	 *
	 * @param provider The specific JCA provider to use, {@code null}
	 *                 implies the default one.
	 *
	 * @return The private Elliptic Curve key, {@code null} if not
	 *         specified by this JWK.
	 *
	 * @throws JOSEException If EC is not supported by the underlying Java
	 *                       Cryptography (JCA) provider or if the JWK
	 *                       parameters are invalid for a private EC key.
	 */
	public ECPrivateKey toECPrivateKey(final Provider provider)
		throws JOSEException {

		if (d == null) {
			// No private 'd' param
			return null;
		}

		ECParameterSpec spec = crv.toECParameterSpec();

		if (spec == null) {
			throw new JOSEException("Couldn't get EC parameter spec for curve " + crv);
		}

		ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(d.decodeToBigInteger(), spec);

		try {
			KeyFactory keyFactory;

			if (provider == null) {
				keyFactory = KeyFactory.getInstance("EC");
			} else {
				keyFactory = KeyFactory.getInstance("EC", provider);
			}

			return (ECPrivateKey) keyFactory.generatePrivate(privateKeySpec);

		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {

			throw new JOSEException(e.getMessage(), e);
		}
	}
	

	/**
	 * Returns a standard {@code java.security.KeyPair} representation of 
	 * this Elliptic Curve JWK. Uses the default JCA provider.
	 * 
	 * @return The Elliptic Curve key pair. The private Elliptic Curve key 
	 *         will be {@code null} if not specified.
	 * 
	 * @throws JOSEException If EC is not supported by the underlying Java
	 *                       Cryptography (JCA) provider or if the JWK
	 *                       parameters are invalid for a public and / or
	 *                       private EC key.
	 */
	public KeyPair toKeyPair()
		throws JOSEException {

		return toKeyPair(null);
	}


	/**
	 * Returns a standard {@code java.security.KeyPair} representation of
	 * this Elliptic Curve JWK.
	 *
	 * @param provider The specific JCA provider to use, {@code null}
	 *                 implies the default one.
	 *
	 * @return The Elliptic Curve key pair. The private Elliptic Curve key
	 *         will be {@code null} if not specified.
	 *
	 * @throws JOSEException If EC is not supported by the underlying Java
	 *                       Cryptography (JCA) provider or if the JWK
	 *                       parameters are invalid for a public and / or
	 *                       private EC key.
	 */
	public KeyPair toKeyPair(final Provider provider)
		throws JOSEException {

		return new KeyPair(toECPublicKey(provider), toECPrivateKey(provider));
	}


	@Override
	public LinkedHashMap<String,?> getRequiredParams() {

		// Put mandatory params in sorted order
		LinkedHashMap<String,String> requiredParams = new LinkedHashMap<>();
		requiredParams.put("crv", crv.toString());
		requiredParams.put("kty", getKeyType().getValue());
		requiredParams.put("x", x.toString());
		requiredParams.put("y", y.toString());
		return requiredParams;
	}


	@Override
	public boolean isPrivate() {

		return d != null;
	}

	
	/**
	 * Returns a copy of this Elliptic Curve JWK with any private values 
	 * removed.
	 *
	 * @return The copied public Elliptic Curve JWK.
	 */
	@Override
	public ECKey toPublicJWK() {

		return new ECKey(getCurve(), getX(), getY(),
			         getKeyUse(), getKeyOperations(), getAlgorithm(), getKeyID(),
			         getX509CertURL(), getX509CertThumbprint(), getX509CertChain());
	}
	

	@Override
	public JSONObject toJSONObject() {

		JSONObject o = super.toJSONObject();

		// Append EC specific attributes
		o.put("crv", crv.toString());
		o.put("x", x.toString());
		o.put("y", y.toString());

		if (d != null) {
			o.put("d", d.toString());
		}
		
		return o;
	}


	/**
	 * Parses a public / private Elliptic Curve JWK from the specified JSON
	 * object string representation.
	 *
	 * @param s The JSON object string to parse. Must not be {@code null}.
	 *
	 * @return The public / private Elliptic Curve JWK.
	 *
	 * @throws ParseException If the string couldn't be parsed to an
	 *                        Elliptic Curve JWK.
	 */
	public static ECKey parse(final String s)
		throws ParseException {

		return parse(JSONObjectUtils.parseJSONObject(s));
	}


	/**
	 * Parses a public / private Elliptic Curve JWK from the specified JSON
	 * object representation.
	 *
	 * @param jsonObject The JSON object to parse. Must not be 
	 *                   {@code null}.
	 *
	 * @return The public / private Elliptic Curve JWK.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to an 
	 *                        Elliptic Curve JWK.
	 */
	public static ECKey parse(final JSONObject jsonObject)
		throws ParseException {

		// Parse the mandatory parameters first
		Curve crv = Curve.parse(JSONObjectUtils.getString(jsonObject, "crv"));
		Base64URL x = new Base64URL(JSONObjectUtils.getString(jsonObject, "x"));
		Base64URL y = new Base64URL(JSONObjectUtils.getString(jsonObject, "y"));

		// Check key type
		KeyType kty = JWKMetadata.parseKeyType(jsonObject);

		if (kty != KeyType.EC) {
			throw new ParseException("The key type \"kty\" must be EC", 0);
		}

		// Get optional private key
		Base64URL d = null;
		if (jsonObject.get("d") != null) {
			d = new Base64URL(JSONObjectUtils.getString(jsonObject, "d"));
		}


		try {
			if (d == null) {
				// Public key
				return new ECKey(crv, x, y,
					JWKMetadata.parseKeyUse(jsonObject),
					JWKMetadata.parseKeyOperations(jsonObject),
					JWKMetadata.parseAlgorithm(jsonObject),
					JWKMetadata.parseKeyID(jsonObject),
					JWKMetadata.parseX509CertURL(jsonObject),
					JWKMetadata.parseX509CertThumbprint(jsonObject),
					JWKMetadata.parseX509CertChain(jsonObject));

			} else {
				// Key pair
				return new ECKey(crv, x, y, d,
					JWKMetadata.parseKeyUse(jsonObject),
					JWKMetadata.parseKeyOperations(jsonObject),
					JWKMetadata.parseAlgorithm(jsonObject),
					JWKMetadata.parseKeyID(jsonObject),
					JWKMetadata.parseX509CertURL(jsonObject),
					JWKMetadata.parseX509CertThumbprint(jsonObject),
					JWKMetadata.parseX509CertChain(jsonObject));
			}

		} catch (IllegalArgumentException ex) {

			// Conflicting 'use' and 'key_ops'
			throw new ParseException(ex.getMessage(), 0);
		}
	}
}
