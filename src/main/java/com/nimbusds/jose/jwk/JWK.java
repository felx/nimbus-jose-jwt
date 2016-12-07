/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2016, Connect2id Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.nimbusds.jose.jwk;


import java.io.Serializable;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.*;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;
import net.minidev.json.JSONAware;
import net.minidev.json.JSONObject;


/**
 * The base abstract class for JSON Web Keys (JWKs). It serialises to a JSON
 * object.
 *
 * <p>The following JSON object members are common to all JWK types:
 *
 * <ul>
 *     <li>{@link #getKeyType kty} (required)
 *     <li>{@link #getKeyUse use} (optional)
 *     <li>{@link #getKeyOperations key_ops} (optional)
 *     <li>{@link #getKeyID kid} (optional)
 * </ul>
 *
 * <p>Example JWK (of the Elliptic Curve type):
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
 * @author Vladimir Dzhuvinov
 * @author Justin Richer
 * @version 2016-12-07
 */
public abstract class JWK implements JSONAware, Serializable {


	private static final long serialVersionUID = 1L;


	/**
	 * The MIME type of JWK objects: 
	 * {@code application/jwk+json; charset=UTF-8}
	 */
	public static final String MIME_TYPE = "application/jwk+json; charset=UTF-8";


	/**
	 * The key type, required.
	 */
	private final KeyType kty;


	/**
	 * The key use, optional.
	 */
	private final KeyUse use;


	/**
	 * The key operations, optional.
	 */
	private final Set<KeyOperation> ops;


	/**
	 * The intended JOSE algorithm for the key, optional.
	 */
	private final Algorithm alg;


	/**
	 * The key ID, optional.
	 */
	private final String kid;


	/**
	 * X.509 certificate URL, optional.
	 */
	private final URI x5u;


	/**
	 * X.509 certificate thumbprint, optional.
	 */
	private final Base64URL x5t;


	/**
	 * The X.509 certificate chain, optional.
	 */
	private final List<Base64> x5c;


	/**
	 * Creates a new JSON Web Key (JWK).
	 *
	 * @param kty The key type. Must not be {@code null}.
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
	public JWK(final KeyType kty,
		   final KeyUse use,
		   final Set<KeyOperation> ops,
		   final Algorithm alg,
		   final String kid,
		   final URI x5u,
		   final Base64URL x5t,
		   final List<Base64> x5c) {

		if (kty == null) {
			throw new IllegalArgumentException("The key type \"kty\" parameter must not be null");
		}

		this.kty = kty;

		if (use != null && ops != null) {
			throw new IllegalArgumentException("They key use \"use\" and key options \"key_opts\" parameters cannot be set together");
		}

		this.use = use;
		this.ops = ops;

		this.alg = alg;
		this.kid = kid;

		this.x5u = x5u;
		this.x5t = x5t;
		this.x5c = x5c;
	}


	/**
	 * Gets the type ({@code kty}) of this JWK.
	 *
	 * @return The key type.
	 */
	public KeyType getKeyType() {

		return kty;
	}


	/**
	 * Gets the use ({@code use}) of this JWK.
	 *
	 * @return The key use, {@code null} if not specified or if the key is
	 *         intended for signing as well as encryption.
	 */
	public KeyUse getKeyUse() {

		return use;
	}


	/**
	 * Gets the operations ({@code key_ops}) for this JWK.
	 *
	 * @return The key operations, {@code null} if not specified.
	 */
	public Set<KeyOperation> getKeyOperations() {

		return ops;
	}


	/**
	 * Gets the intended JOSE algorithm ({@code alg}) for this JWK.
	 *
	 * @return The intended JOSE algorithm, {@code null} if not specified.
	 */
	public Algorithm getAlgorithm() {

		return alg;
	}


	/**
	 * Gets the ID ({@code kid}) of this JWK. The key ID can be used to 
	 * match a specific key. This can be used, for instance, to choose a 
	 * key within a {@link JWKSet} during key rollover. The key ID may also 
	 * correspond to a JWS/JWE {@code kid} header parameter value.
	 *
	 * @return The key ID, {@code null} if not specified.
	 */
	public String getKeyID() {

		return kid;
	}


	/**
	 * Gets the X.509 certificate URL ({@code x5u}) of this JWK.
	 *
	 * @return The X.509 certificate URL, {@code null} if not specified.
	 */
	public URI getX509CertURL() {

		return x5u;
	}


	/**
	 * Gets the X.509 certificate SHA-1 thumbprint ({@code x5t}) of this
	 * JWK.
	 *
	 * @return The X.509 certificate SHA-1 thumbprint, {@code null} if not
	 *         specified.
	 */
	public Base64URL getX509CertThumbprint() {

		return x5t;
	}


	/**
	 * Gets the X.509 certificate chain ({@code x5c}) of this JWK.
	 *
	 * @return The X.509 certificate chain as a unmodifiable list,
	 *         {@code null} if not specified.
	 */
	public List<Base64> getX509CertChain() {

		if (x5c == null) {
			return null;
		}

		return Collections.unmodifiableList(x5c);
	}


	/**
	 * Returns the required JWK parameters. Intended as input for JWK
	 * thumbprint computation. See RFC 7638 for more information.
	 *
	 * @return The required JWK parameters, sorted alphanumerically by key
	 *         name and ready for JSON serialisation.
	 */
	public abstract LinkedHashMap<String,?> getRequiredParams();


	/**
	 * Computes the SHA-256 thumbprint of this JWK. See RFC 7638 for more
	 * information.
	 *
	 * @return The SHA-256 thumbprint.
	 *
	 * @throws JOSEException If the SHA-256 hash algorithm is not
	 *                       supported.
	 */
	public Base64URL computeThumbprint()
		throws JOSEException {

		return computeThumbprint("SHA-256");
	}


	/**
	 * Computes the thumbprint of this JWK using the specified hash
	 * algorithm. See RFC 7638 for more information.
	 *
	 * @param hashAlg The hash algorithm. Must not be {@code null}.
	 *
	 * @return The SHA-256 thumbprint.
	 *
	 * @throws JOSEException If the hash algorithm is not supported.
	 */
	public Base64URL computeThumbprint(final String hashAlg)
		throws JOSEException {

		return ThumbprintUtils.compute(hashAlg, this);
	}


	/**
	 * Returns {@code true} if this JWK contains private or sensitive
	 * (non-public) parameters.
	 *
	 * @return {@code true} if this JWK contains private parameters, else
	 *         {@code false}.
	 */
	public abstract boolean isPrivate();


	/**
	 * Creates a copy of this JWK with all private or sensitive parameters 
	 * removed.
	 * 
	 * @return The newly created public JWK, or {@code null} if none can be
	 *         created.
	 */
	public abstract JWK toPublicJWK();


	/**
	 * Returns the size of this JWK.
	 *
	 * @return The JWK size, in bits.
	 */
	public abstract int size();


	/**
	 * Returns a JSON object representation of this JWK. This method is 
	 * intended to be called from extending classes.
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * {
	 *   "kty" : "RSA",
	 *   "use" : "sig",
	 *   "kid" : "fd28e025-8d24-48bc-a51a-e2ffc8bc274b"
	 * }
	 * </pre>
	 *
	 * @return The JSON object representation.
	 */
	public JSONObject toJSONObject() {

		JSONObject o = new JSONObject();

		o.put("kty", kty.getValue());

		if (use != null) {
			o.put("use", use.identifier());
		}

		if (ops != null) {

			List<String> sl = new ArrayList<>(ops.size());

			for (KeyOperation op: ops) {
				sl.add(op.identifier());
			}

			o.put("key_ops", sl);
		}

		if (alg != null) {
			o.put("alg", alg.getName());
		}

		if (kid != null) {
			o.put("kid", kid);
		}

		if (x5u != null) {
			o.put("x5u", x5u.toString());
		}

		if (x5t != null) {
			o.put("x5t", x5t.toString());
		}

		if (x5c != null) {
			o.put("x5c", x5c);
		}

		return o;
	}


	/**
	 * Returns the JSON object string representation of this JWK.
	 *
	 * @return The JSON object string representation.
	 */
	@Override
	public String toJSONString() {

		return toJSONObject().toString();
	}


	/**
	 * @see #toJSONString
	 */
	@Override
	public String toString() {

		return toJSONObject().toString();
	}


	/**
	 * Parses a JWK from the specified JSON object string representation. 
	 * The JWK must be an {@link ECKey}, an {@link RSAKey}, or a 
	 * {@link OctetSequenceKey}.
	 *
	 * @param s The JSON object string to parse. Must not be {@code null}.
	 *
	 * @return The JWK.
	 *
	 * @throws ParseException If the string couldn't be parsed to a
	 *                        supported JWK.
	 */
	public static JWK parse(final String s)
		throws ParseException {

		return parse(JSONObjectUtils.parse(s));
	}


	/**
	 * Parses a JWK from the specified JSON object representation. The JWK 
	 * must be an {@link ECKey}, an {@link RSAKey}, or a 
	 * {@link OctetSequenceKey}.
	 *
	 * @param jsonObject The JSON object to parse. Must not be 
	 *                   {@code null}.
	 *
	 * @return The JWK.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to a 
	 *                        supported JWK.
	 */
	public static JWK parse(final JSONObject jsonObject)
		throws ParseException {

		KeyType kty = KeyType.parse(JSONObjectUtils.getString(jsonObject, "kty"));

		if (kty == KeyType.EC) {
			
			return ECKey.parse(jsonObject);

		} else if (kty == KeyType.RSA) {
			
			return RSAKey.parse(jsonObject);

		} else if (kty == KeyType.OCT) {
			
			return OctetSequenceKey.parse(jsonObject);

		} else {

			throw new ParseException("Unsupported key type \"kty\" parameter: " + kty, 0);
		}
	}
	
	
	/**
	 * Parses a public {@link RSAKey RSA} or {@link ECKey EC JWK} from the
	 * specified X.509 certificate. Requires BouncyCastle.
	 *
	 * <p><strong>Important:</strong> The X.509 certificate is not
	 * validated!
	 *
	 * <p>Set the following JWK parameters:
	 *
	 * <ul>
	 *     <li>For an EC key the curve is obtained from the subject public
	 *         key info algorithm parameters.
	 *     <li>The JWK use inferred by {@link KeyUse#from}.
	 *     <li>The JWK ID from the X.509 serial number (in base 10).
	 *     <li>The JWK X.509 certificate chain (this certificate only).
	 *     <li>The JWK X.509 certificate SHA-1 thumbprint.
	 * </ul>
	 *
	 * @param cert The X.509 certificate. Must not be {@code null}.
	 *
	 * @return The public RSA or EC JWK.
	 *
	 * @throws JOSEException If parsing failed.
	 */
	public static JWK parse(final X509Certificate cert)
		throws JOSEException {
		
		if (cert.getPublicKey() instanceof RSAPublicKey) {
			return RSAKey.parse(cert);
		} else if (cert.getPublicKey() instanceof ECPublicKey) {
			return ECKey.parse(cert);
		} else {
			throw new JOSEException("Unsupported public key algorithm: " + cert.getPublicKey().getAlgorithm());
		}
	}
}
