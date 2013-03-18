package com.nimbusds.jose.jwk;


import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPublicKeySpec;
import java.text.ParseException;

import net.jcip.annotations.Immutable;

import net.minidev.json.JSONObject;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;


/**
 * Public and private {@link KeyType#EC Elliptic Curve} JSON Web Key (JWK). 
 * This class is immutable.
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
 * <p>See http://en.wikipedia.org/wiki/Elliptic_curve_cryptography
 *
 * @author Vladimir Dzhuvinov
 * @author Justin Richer
 * @version $version$ (2013-03-15)
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
		 * P-256 curve.
		 */
		public static final Curve P_256 = new Curve("P-256");


		/**
		 * P-384 curve.
		 */
		public static final Curve P_384 = new Curve("P-384");


		/**
		 * P-521 curve.
		 */
		public static final Curve P_521 = new Curve("P-521");


		/**
		 * The curve name.
		 */
		private final String name;


		/**
		 * Creates a new cryptographic curve with the specified name.
		 *
		 * @param name The name of the cryptographic curve. Must not be
		 *             {@code null}.
		 */
		public Curve(final String name) {

			if (name == null) {
				throw new IllegalArgumentException("The cryptographic curve name must not be null");
			}

			this.name = name;
		}


		/**
		 * Gets the name of this cryptographic curve.
		 *
		 * @return The name.
		 */
		public String getName() {

			return name;
		}


		/**
		 * @see #getName
		 */
		@Override
		public String toString() {

			return getName();
		}


		/**
		 * Overrides {@code Object.equals()}.
		 *
		 * @param object The object to compare to.
		 *
		 * @return {@code true} if the objects have the same value,
		 *         otherwise {@code false}.
		 */
		@Override
		public boolean equals(final Object object) {

			return object != null && 
					object instanceof Curve && 
					this.toString().equals(object.toString());
		}


		/**
		 * Parses a cryptographic curve from the specified string.
		 *
		 * @param s The string to parse. Must not be {@code null}.
		 *
		 * @return The cryptographic curve.
		 *
		 * @throws ParseException If the string couldn't be parsed.
		 */
		public static Curve parse(final String s) 
				throws ParseException {

			if (s == null) {
				throw new IllegalArgumentException("The cryptographic curve sting must not be null");
			}

			if (s == P_256.getName()) {
				return P_256;
			} else if (s == P_384.getName()) {
				return P_384;
			} else if (s == P_521.getName()) {
				return P_521;
			} else {
				return new Curve(s);
			}
		}
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
	 * @param x   The 'x' coordinate for the elliptic curve point. It is 
	 *            represented as the Base64URL encoding of the coordinate's 
	 *            big endian representation. Must not be {@code null}.
	 * @param y   The 'y' coordinate for the elliptic curve point. It is 
	 *            represented as the Base64URL encoding of the coordinate's 
	 *            big endian representation. Must not be {@code null}.
	 * @param use The key use, {@code null} if not specified.
	 * @param alg The intended JOSE algorithm for the key, {@code null} if
	 *            not specified.
	 * @param kid The key ID, {@code null} if not specified.
	 */
	public ECKey(final Curve crv, final Base64URL x, final Base64URL y, 
		     final Use use, final Algorithm alg, final String kid) {

		this(crv, x, y, use, alg, kid, null);
	}


	/**
	 * Creates a new public / private Elliptic Curve JSON Web Key (JWK) 
	 * with the specified parameters.
	 *
	 * @param crv The cryptographic curve. Must not be {@code null}.
	 * @param x   The 'x' coordinate for the elliptic curve point. It is 
	 *            represented as the Base64URL encoding of the coordinate's 
	 *            big endian representation. Must not be {@code null}.
	 * @param y   The 'y' coordinate for the elliptic curve point. It is 
	 *            represented as the Base64URL encoding of the coordinate's 
	 *            big endian representation. Must not be {@code null}.
	 * @param use The key use, {@code null} if not specified.
	 * @param alg The intended JOSE algorithm for the key, {@code null} if
	 *            not specified.
	 * @param kid The key ID, {@code null} if not specified.
	 * @param d   The 'd' coordinate for the elliptic curve point. It is 
	 *            represented as the Base64URL encoding of the coordinate's 
	 *            big endian representation. May be {@code null} if this is
	 *            a public key.
	 */
	public ECKey(final Curve crv, final Base64URL x, final Base64URL y, 
		     final Use use, final Algorithm alg, final String kid, 
		     final Base64URL d) {

		super(KeyType.EC, use, alg, kid);

		if (crv == null) {
			throw new IllegalArgumentException("The curve must not be null");
		}

		this.crv = crv;

		if (x == null) {
			throw new IllegalArgumentException("The x coordinate must not be null");
		}

		this.x = x;

		if (y == null) {
			throw new IllegalArgumentException("The y coordinate must not be null");
		}

		this.y = y;
		
		this.d = d;
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
	 * Gets the public 'x' coordinate for the elliptic curve point. It is 
	 * represented as the Base64URL encoding of the coordinate's big endian 
	 * representation.
	 *
	 * @return The 'x' coordinate.
	 */
	public Base64URL getX() {

		return x;
	}


	/**
	 * Gets the public 'y' coordinate for the elliptic curve point. It is 
	 * represented as the Base64URL encoding of the coordinate's big endian 
	 * representation.
	 *
	 * @return The 'y' coordinate.
	 */
	public Base64URL getY() {

		return y;
	}

	
	/**
	 * Gets the private 'd' coordinate for the elliptic curve point. It is 
	 * represented as the Base64URL encoding of the coordinate's big endian 
	 * representation.
	 *
	 * @return The 'd' coordinate, {@code null} if not specified (for a 
	 *         public key).
	 */
	public Base64URL getD() {

		return d;
	}

	/**
	 * Gets a copy of the public key represented by this JWK.
	 * 
	 * @throws UnsupportedOperationException - not yet implemented
	 */
	public ECPublicKey toECPublicKey() {
		// TODO
		throw new UnsupportedOperationException("Not yet implemented.");
	}
	
	/**
	 * Gets a copy of the public key represented by this JWK.
	 * 
	 * @throws UnsupportedOperationException - not yet implemented
	 */
	public ECPrivateKey toECprivateKey() {
		// TODO
		throw new UnsupportedOperationException("Not yet implemented.");
	}
	
	/**
	 * Returns the EC public and private keys represented by this object.
	 * 
	 * @return the EC key pair
	 */
	public KeyPair toKeyPair() {
		return new KeyPair(toECPublicKey(), toECprivateKey());		
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
	 * object representation.
	 *
	 * @param jsonObject The JSON object to parse. Must not be 
	 *                   {@code null}.
	 *
	 * @return The public / private Elliptic Curve JWK.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to a 
	 *                        valid Elliptic Curve JWK.
	 */
	public static ECKey parse(final JSONObject jsonObject)
		throws ParseException {

		// Parse the mandatory parameters first
		Curve crv = Curve.parse(JSONObjectUtils.getString(jsonObject, "crv"));
		Base64URL x = new Base64URL(JSONObjectUtils.getString(jsonObject, "x"));
		Base64URL y = new Base64URL(JSONObjectUtils.getString(jsonObject, "y"));

		// Check key type
		KeyType kty = KeyType.parse(JSONObjectUtils.getString(jsonObject, "kty"));
		if (kty != KeyType.EC) {
			throw new ParseException("The key type \"kty\" must be EC", 0);
		}
		
		// optional private key
		Base64URL d = null;
		if (jsonObject.get("d") != null) {
			d = new Base64URL(JSONObjectUtils.getString(jsonObject, "d"));
		}
		
		// Get optional key use
		Use use = JWK.parseKeyUse(jsonObject);

		// Get optional intended algorithm
		Algorithm alg = JWK.parseAlgorithm(jsonObject);

		// Get optional key ID
		String kid = JWK.parseKeyID(jsonObject);

		return new ECKey(crv, x, y, use, alg, kid, d);
	}
}
