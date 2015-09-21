package com.nimbusds.jose.jwk;


import java.net.URI;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedHashMap;
import java.util.List;
import java.text.ParseException;
import java.util.Map;
import java.util.Set;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import net.jcip.annotations.Immutable;

import net.minidev.json.JSONObject;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;


/**
 * {@link KeyType#OCT Octet sequence} JSON Web Key (JWK), used to represent
 * symmetric keys. This class is immutable.
 *
 * <p>Octet sequence JWKs should specify the algorithm intended to be used with
 * the key, unless the application uses other means or convention to determine
 * the algorithm used.
 *
 * <p>Example JSON object representation of an octet sequence JWK:
 *
 * <pre>
 * {
 *   "kty" : "oct",
 *   "alg" : "A128KW",
 *   "k"   : "GawgguFyGrWKav7AX4VKUg"
 * }
 * </pre>
 * 
 * @author Justin Richer
 * @author Vladimir Dzhuvinov
 * @version 2015-09-21
 */
@Immutable
public final class OctetSequenceKey extends JWK {


	/**
	 * The key value.
	 */
	private final Base64URL k;


	/**
	 * Builder for constructing octet sequence JWKs.
	 *
	 * <p>Example usage:
	 *
	 * <pre>
	 * OctetSequenceKey key = new OctetSequenceKey.Builder(k).
	 *                        algorithm(JWSAlgorithm.HS512).
	 *                        keyID("123").
	 *                        build();
	 * </pre>
	 */
	public static class Builder {


		/**
		 * The key value.
		 */
		private final Base64URL k;


		/**
		 * The public key use, optional.
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
		 * Creates a new octet sequence JWK builder.
		 *
		 * @param k The key value. It is represented as the Base64URL 
		 *          encoding of value's big endian representation. Must
		 *          not be {@code null}.
		 */
		public Builder(final Base64URL k) {

			if (k == null) {
				throw new IllegalArgumentException("The key value must not be null");
			}

			this.k = k;
		}


		/**
		 * Creates a new octet sequence JWK builder.
		 *
		 * @param key The key value. Must not be empty byte array or
		 *            {@code null}.
		 */
		public Builder(final byte[] key) {

			this(Base64URL.encode(key));

			if (key.length == 0) {
				throw new IllegalArgumentException("The key must have a positive length");
			}
		}


		/**
		 * Creates a new octet sequence JWK builder.
		 *
		 * @param secretKey The secret key to represent. Must not be
		 *                  {@code null}.
		 */
		public Builder(final SecretKey secretKey) {

			this(secretKey.getEncoded());
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
		 * Sets the operations ({@code key_ops}) of the JWK (for a
		 * non-public key).
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
		public OctetSequenceKey build() {

			try {
				return new OctetSequenceKey(k, use, ops, alg, kid, x5u, x5t, x5c);

			} catch (IllegalArgumentException e) {

				throw new IllegalStateException(e.getMessage(), e);
			}
		}
	}

	
	/**
	 * Creates a new octet sequence JSON Web Key (JWK) with the specified
	 * parameters.
	 *
	 * @param k   The key value. It is represented as the Base64URL 
	 *            encoding of the value's big endian representation. Must
	 *            not be {@code null}.
	 * @param use The key use, {@code null} if not specified or if the key
	 *            is intended for signing as well as encryption.
	 * @param ops The key operations, {@code null} if not specified.
	 * @param alg The intended JOSE algorithm for the key, {@code null} if
	 *            not specified.
	 * @param kid The key ID. {@code null} if not specified.
	 * @param x5u The X.509 certificate URL, {@code null} if not specified.
	 * @param x5t The X.509 certificate thumbprint, {@code null} if not
	 *            specified.
	 * @param x5c The X.509 certificate chain, {@code null} if not 
	 *            specified.
	 */
	public OctetSequenceKey(final Base64URL k,
				final KeyUse use, final Set<KeyOperation> ops, final Algorithm alg, final String kid,
		                final URI x5u, final Base64URL x5t, final List<Base64> x5c) {
	
		super(KeyType.OCT, use, ops, alg, kid, x5u, x5t, x5c);

		if (k == null) {
			throw new IllegalArgumentException("The key value must not be null");
		}

		this.k = k;
	}
    

	/**
	 * Returns the value of this octet sequence key. 
	 *
	 * @return The key value. It is represented as the Base64URL encoding
	 *         of the value's big endian representation.
	 */
	public Base64URL getKeyValue() {

		return k;
	}
	
	
	/**
	 * Returns a copy of this octet sequence key value as a byte array.
	 * 
	 * @return The key value as a byte array.
	 */
	public byte[] toByteArray() {

		return getKeyValue().decode();
	}


	/**
	 * Returns a secret key representation of this octet sequence key.
	 *
	 * @return The secret key representation, with an algorithm set to
	 *         {@code NONE}.
	 */
	public SecretKey toSecretKey() {

		return toSecretKey("NONE");
	}


	/**
	 * Returns a secret key representation of this octet sequence key with
	 * the specified Java Cryptography Architecture (JCA) algorithm.
	 *
	 * @param jcaAlg The JCA algorithm. Must not be {@code null}.
	 *
	 * @return The secret key representation.
	 */
	public SecretKey toSecretKey(final String jcaAlg) {

		return new SecretKeySpec(toByteArray(), jcaAlg);
	}


	@Override
	public Base64URL computeThumbprint(final String hashAlg)
		throws JOSEException {

		// Put mandatory params in sorted order
		Map<String,String> mandatoryParams = new LinkedHashMap<>();
		mandatoryParams.put("k", k.toString());
		mandatoryParams.put("kty", getKeyType().toString());
		MessageDigest md;

		try {
			md = MessageDigest.getInstance(hashAlg);
		} catch (NoSuchAlgorithmException e) {
			throw new JOSEException("Unsupported hash algorithm: " + e.getMessage(), e);
		}

		md.update(JSONObject.toJSONString(mandatoryParams).getBytes(Charset.forName("UTF-8")));

		return Base64URL.encode(md.digest());
	}


	/**
	 * Octet sequence (symmetric) keys are never considered public, this 
	 * method always returns {@code true}.
	 *
	 * @return {@code true}
	 */
	@Override
	public boolean isPrivate() {

		return true;
	}


	/**
	 * Octet sequence (symmetric) keys are never considered public, this 
	 * method always returns {@code null}.
	 *
	 * @return {@code null}
	 */
	@Override
	public OctetSequenceKey toPublicJWK() {

		return null;
	}
	

	@Override
	public JSONObject toJSONObject() {

		JSONObject o = super.toJSONObject();

		// Append key value
		o.put("k", k.toString());
		
		return o;
	}


	/**
	 * Parses an octet sequence JWK from the specified JSON object string 
	 * representation.
	 *
	 * @param s The JSON object string to parse. Must not be {@code null}.
	 *
	 * @return The octet sequence JWK.
	 *
	 * @throws ParseException If the string couldn't be parsed to an octet
	 *                        sequence JWK.
	 */
	public static OctetSequenceKey parse(final String s)
		throws ParseException {

		return parse(JSONObjectUtils.parseJSONObject(s));
	}

	
	/**
	 * Parses an octet sequence JWK from the specified JSON object 
	 * representation.
	 *
	 * @param jsonObject The JSON object to parse. Must not be 
	 *                   @code null}.
	 *
	 * @return The octet sequence JWK.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to an
	 *                        octet sequence JWK.
	 */
	public static OctetSequenceKey parse(final JSONObject jsonObject) 
		throws ParseException {

		// Parse the mandatory parameters first
		Base64URL k = new Base64URL(JSONObjectUtils.getString(jsonObject, "k"));

		// Check key type
		KeyType kty = JWKMetadata.parseKeyType(jsonObject);

		if (kty != KeyType.OCT) {

			throw new ParseException("The key type \"kty\" must be oct", 0);
		}

		return new OctetSequenceKey(k,
			JWKMetadata.parseKeyUse(jsonObject),
			JWKMetadata.parseKeyOperations(jsonObject),
			JWKMetadata.parseAlgorithm(jsonObject),
			JWKMetadata.parseKeyID(jsonObject),
			JWKMetadata.parseX509CertURL(jsonObject),
			JWKMetadata.parseX509CertThumbprint(jsonObject),
			JWKMetadata.parseX509CertChain(jsonObject));
	}
}
