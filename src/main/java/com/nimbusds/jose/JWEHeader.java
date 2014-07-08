package com.nimbusds.jose;


import java.net.URL;
import java.text.ParseException;
import java.util.*;

import net.minidev.json.JSONObject;

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jose.util.X509CertChainUtils;


/**
 * JSON Web Encryption (JWE) header.
 *
 * <p>Supports all {@link #getRegisteredParameterNames registered header
 * parameters} of the JWE specification:
 *
 * <ul>
 *     <li>alg
 *     <li>enc
 *     <li>epk
 *     <li>zip
 *     <li>jku
 *     <li>jwk
 *     <li>x5u
 *     <li>x5t
 *     <li>x5c
 *     <li>kid
 *     <li>typ
 *     <li>cty
 *     <li>crit
 *     <li>apu
 *     <li>apv
 *     <li>p2s
 *     <li>p2c
 * </ul>
 *
 * <p>The header may also include {@link #getCustomParameters custom
 * parameters}; these will be serialised and parsed along the registered ones.
 *
 * <p>Example header:
 *
 * <pre>
 * { 
 *   "alg" : "RSA1_5",
 *   "enc" : "A128CBC-HS256"
 * }
 * </pre>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-07-08)
 */
public class JWEHeader extends CommonSEHeader {


	/**
	 * The registered parameter names.
	 */
	private static final Set<String> REGISTERED_PARAMETER_NAMES;


	/**
	 * Initialises the registered parameter name set.
	 */
	static {
		Set<String> p = new HashSet<String>();

		p.add("alg");
		p.add("enc");
		p.add("epk");
		p.add("zip");
		p.add("jku");
		p.add("jwk");
		p.add("x5u");
		p.add("x5t");
		p.add("x5c");
		p.add("kid");
		p.add("typ");
		p.add("cty");
		p.add("crit");
		p.add("apu");
		p.add("apv");
		p.add("p2s");
		p.add("p2c");

		REGISTERED_PARAMETER_NAMES = Collections.unmodifiableSet(p);
	}


	/**
	 * The encryption method ({@code enc}) parameter.
	 */
	private final EncryptionMethod enc;


	/**
	 * The ephemeral public key ({@code epk}) parameter.
	 */
	private final ECKey epk;


	/**
	 * The compression algorithm ({@code zip}) parameter.
	 */
	private final CompressionAlgorithm zip;


	/**
	 * The agreement PartyUInfo ({@code apu}) parameter.
	 */
	private final Base64URL apu;
	
	
	/**
	 * The agreement PartyVInfo ({@code apv}) parameter.
	 */
	private final Base64URL apv;


	/**
	 * The PBES2 salt ({@code p2s}) parameter.
	 */
	private final Base64URL p2s;


	/**
	 * The PBES2 count ({@code p2c}) parameter.
	 */
	private final int p2c;


	/**
	 * Creates a new JSON Web Encryption (JWE) header.
	 *
	 * <p>Note: Use {@link PlainHeader} to create a header with algorithm
	 * {@link Algorithm#NONE none}.
	 *
	 * @param alg The JWE algorithm parameter. Must not be "none" or
	 *            {@code null}.
	 * @param enc The encryption method parameter. Must not be 
	 *            {@code null}.
	 */
	public JWEHeader(final JWEAlgorithm alg, final EncryptionMethod enc) {

		this(
			alg, enc,
			null, null, null, null, null, null, null, null, null,
			null, null, null, null, null, 0,
			null, null);
	}


	/**
	 * Creates a new JSON Web Encryption (JWE) header.
	 *
	 * <p>Note: Use {@link PlainHeader} to create a header with algorithm
	 * {@link Algorithm#NONE none}.
	 *
	 * @param alg             The JWE algorithm ({@code alg}) parameter.
	 *                        Must not be "none" or {@code null}.
	 * @param enc             The encryption method parameter. Must not be
	 *                        {@code null}.
	 * @param typ             The type ({@code typ}) parameter,
	 *                        {@code null} if not specified.
	 * @param cty             The content type ({@code cty}) parameter,
	 *                        {@code null} if not specified.
	 * @param crit            The names of the critical header
	 *                        ({@code crit}) parameters, empty set or
	 *                        {@code null} if none.
	 * @param jku             The JSON Web Key (JWK) Set URL ({@code jku})
	 *                        parameter, {@code null} if not specified.
	 * @param jwk             The X.509 certificate URL ({@code jwk})
	 *                        parameter, {@code null} if not specified.
	 * @param x5u             The X.509 certificate URL parameter
	 *                        ({@code x5u}), {@code null} if not specified.
	 * @param x5t             The X.509 certificate thumbprint
	 *                        ({@code x5t}) parameter, {@code null} if not
	 *                        specified.
	 * @param x5c             The X.509 certificate chain ({@code x5c})
	 *                        parameter, {@code null} if not specified.
	 * @param kid             The key ID ({@code kid}) parameter,
	 *                        {@code null} if not specified.
	 * @param epk             The Ephemeral Public Key ({@code epk})
	 *                        parameter, {@code null} if not specified.
	 * @param zip             The compression algorithm ({@code zip})
	 *                        parameter, {@code null} if not specified.
	 * @param apu             The agreement PartyUInfo ({@code apu})
	 *                        parameter, {@code null} if not specified.
	 * @param apv             The agreement PartyVInfo ({@code apv})
	 *                        parameter, {@code null} if not specified.
	 * @param p2s             The PBES2 salt ({@code p2s}) parameter,
	 *                        {@code null} if not specified.
	 * @param p2c             The PBES2 count ({@code p2c}) parameter, zero
	 *                        if not specified. Must not be negative.
	 * @param customParams    The custom parameters, empty map or
	 *                        {@code null} if none.
	 * @param parsedBase64URL The parsed Base64URL, {@code null} if the
	 *                        header is created from scratch.
	 */
	public JWEHeader(final Algorithm alg,
			 final EncryptionMethod enc,
			 final JOSEObjectType typ,
			 final String cty,
			 final Set<String> crit,
			 final URL jku,
			 final JWK jwk,
			 final URL x5u,
			 final Base64URL x5t,
			 final List<Base64> x5c,
			 final String kid,
			 final ECKey epk,
			 final CompressionAlgorithm zip,
			 final Base64URL apu,
			 final Base64URL apv,
			 final Base64URL p2s,
			 final int p2c,
			 final Map<String,Object> customParams,
			 final Base64URL parsedBase64URL) {

		super(alg, typ, cty, crit, jku, jwk, x5u, x5t, x5c, kid, customParams, parsedBase64URL);

		if (alg.getName().equals(Algorithm.NONE.getName())) {
			throw new IllegalArgumentException("The JWE algorithm cannot be \"none\"");
		}

		if (enc == null) {
			throw new IllegalArgumentException("The encryption method \"enc\" parameter must not be null");
		}

		this.enc = enc;

		this.epk = epk;
		this.zip = zip;
		this.apu = apu;
		this.apv = apv;
		this.p2s = p2s;
		this.p2c = p2c;
	}


	/**
	 * Gets the registered parameter names for JWE headers.
	 *
	 * @return The registered parameter names, as an unmodifiable set.
	 */
	public static Set<String> getRegisteredParameterNames() {

		return REGISTERED_PARAMETER_NAMES;
	}


	/**
	 * Gets the algorithm ({@code alg}) parameter.
	 *
	 * @return The algorithm parameter.
	 */
	public JWEAlgorithm getAlgorithm() {

		return (JWEAlgorithm)alg;
	}


	/**
	 * Gets the encryption method ({@code enc}) parameter.
	 *
	 * @return The encryption method parameter.
	 */
	public EncryptionMethod getEncryptionMethod() {

		return enc;
	}


	/**
	 * Sets the type ({@code typ}) parameter.
	 *
	 * @param typ The type parameter, {@code null} if not specified.
	 *
	 * @return The new header.
	 */
	public JWEHeader setType(final JOSEObjectType typ) {

		return new JWEHeader(
			getAlgorithm(),
			getEncryptionMethod(),
			typ,
			getContentType(),
			getCriticalHeaders(),
			getJWKURL(),
			getJWK(),
			getX509CertURL(),
			getX509CertThumbprint(),
			getX509CertChain(),
			getKeyID(),
			getEphemeralPublicKey(),
			getCompressionAlgorithm(),
			getAgreementPartyUInfo(),
			getAgreementPartyVInfo(),
			getPBES2Salt(),
			getPBES2Count(),
			getCustomParameters(),
			getParsedBase64URL()
		);
	}


	/**
	 * Sets the content type ({@code cty}) parameter.
	 *
	 * @param cty The content type parameter, {@code null} if not
	 *            specified.
	 *
	 * @return The new header.
	 */
	public JWEHeader setContentType(final String cty) {

		return new JWEHeader(
			getAlgorithm(),
			getEncryptionMethod(),
			getType(),
			cty,
			getCriticalHeaders(),
			getJWKURL(),
			getJWK(),
			getX509CertURL(),
			getX509CertThumbprint(),
			getX509CertChain(),
			getKeyID(),
			getEphemeralPublicKey(),
			getCompressionAlgorithm(),
			getAgreementPartyUInfo(),
			getAgreementPartyVInfo(),
			getPBES2Salt(),
			getPBES2Count(),
			getCustomParameters(),
			getParsedBase64URL()
		);
	}


	/**
	 * Sets the critical headers ({@code crit}) parameter.
	 *
	 * @param crit The names of the critical header parameters, empty set
	 *             or {@code null} if none.
	 *
	 * @return The new header.
	 */
	public JWEHeader setCriticalHeaders(final Set<String> crit) {

		return new JWEHeader(
			getAlgorithm(),
			getEncryptionMethod(),
			getType(),
			getContentType(),
			crit,
			getJWKURL(),
			getJWK(),
			getX509CertURL(),
			getX509CertThumbprint(),
			getX509CertChain(),
			getKeyID(),
			getEphemeralPublicKey(),
			getCompressionAlgorithm(),
			getAgreementPartyUInfo(),
			getAgreementPartyVInfo(),
			getPBES2Salt(),
			getPBES2Count(),
			getCustomParameters(),
			getParsedBase64URL()
		);
	}


	/**
	 * Sets the JSON Web Key (JWK) Set URL ({@code jku}) parameter.
	 *
	 * @param jku The JSON Web Key (JWK) Set URL parameter, {@code null} if
	 *            not specified.
	 *
	 * @return The new header.
	 */
	public JWEHeader setJWKURL(final URL jku) {

		return new JWEHeader(
			getAlgorithm(),
			getEncryptionMethod(),
			getType(),
			getContentType(),
			getCriticalHeaders(),
			jku,
			getJWK(),
			getX509CertURL(),
			getX509CertThumbprint(),
			getX509CertChain(),
			getKeyID(),
			getEphemeralPublicKey(),
			getCompressionAlgorithm(),
			getAgreementPartyUInfo(),
			getAgreementPartyVInfo(),
			getPBES2Salt(),
			getPBES2Count(),
			getCustomParameters(),
			getParsedBase64URL()
		);
	}


	/**
	 * Sets the JSON Web Key (JWK) ({@code jwk}) parameter.
	 *
	 * @param jwk The JSON Web Key (JWK) ({@code jwk}) parameter,
	 *            {@code null} if not specified.
	 *
	 * @return The new header.
	 */
	public JWEHeader setJWK(final JWK jwk) {

		return new JWEHeader(
			getAlgorithm(),
			getEncryptionMethod(),
			getType(),
			getContentType(),
			getCriticalHeaders(),
			getJWKURL(),
			jwk,
			getX509CertURL(),
			getX509CertThumbprint(),
			getX509CertChain(),
			getKeyID(),
			getEphemeralPublicKey(),
			getCompressionAlgorithm(),
			getAgreementPartyUInfo(),
			getAgreementPartyVInfo(),
			getPBES2Salt(),
			getPBES2Count(),
			getCustomParameters(),
			getParsedBase64URL()
		);
	}


	/**
	 * Sets the X.509 certificate URL ({@code x5u}) parameter.
	 *
	 * @param x5u The X.509 certificate URL parameter, {@code null} if not
	 *            specified.
	 *
	 * @return The new header.
	 */
	public JWEHeader setX509CertURL(final URL x5u) {

		return new JWEHeader(
			getAlgorithm(),
			getEncryptionMethod(),
			getType(),
			getContentType(),
			getCriticalHeaders(),
			getJWKURL(),
			getJWK(),
			x5u,
			getX509CertThumbprint(),
			getX509CertChain(),
			getKeyID(),
			getEphemeralPublicKey(),
			getCompressionAlgorithm(),
			getAgreementPartyUInfo(),
			getAgreementPartyVInfo(),
			getPBES2Salt(),
			getPBES2Count(),
			getCustomParameters(),
			getParsedBase64URL()
		);
	}


	/**
	 * Sets the X.509 certificate thumbprint ({@code x5t}) parameter.
	 *
	 * @param x5t The X.509 certificate thumbprint parameter, {@code null}
	 *            if not specified.
	 *
	 * @return The new header.
	 */
	public JWEHeader setX509CertThumbprint(final Base64URL x5t) {

		return new JWEHeader(
			getAlgorithm(),
			getEncryptionMethod(),
			getType(),
			getContentType(),
			getCriticalHeaders(),
			getJWKURL(),
			getJWK(),
			getX509CertURL(),
			x5t,
			getX509CertChain(),
			getKeyID(),
			getEphemeralPublicKey(),
			getCompressionAlgorithm(),
			getAgreementPartyUInfo(),
			getAgreementPartyVInfo(),
			getPBES2Salt(),
			getPBES2Count(),
			getCustomParameters(),
			getParsedBase64URL()
		);
	}


	/**
	 * Sets the X.509 certificate chain parameter ({@code x5c})
	 * corresponding to the key used to sign or encrypt the JWS / JWE
	 * object.
	 *
	 * @param x5c The X.509 certificate chain parameter, {@code null} if
	 *            not specified.
	 *
	 * @return The new header.
	 */
	public JWEHeader setX509CertChain(final List<Base64> x5c) {

		return new JWEHeader(
			getAlgorithm(),
			getEncryptionMethod(),
			getType(),
			getContentType(),
			getCriticalHeaders(),
			getJWKURL(),
			getJWK(),
			getX509CertURL(),
			getX509CertThumbprint(),
			x5c,
			getKeyID(),
			getEphemeralPublicKey(),
			getCompressionAlgorithm(),
			getAgreementPartyUInfo(),
			getAgreementPartyVInfo(),
			getPBES2Salt(),
			getPBES2Count(),
			getCustomParameters(),
			getParsedBase64URL()
		);
	}


	/**
	 * Sets the key ID ({@code kid}) parameter.
	 *
	 * @param kid The key ID parameter, {@code null} if not specified.
	 *
	 * @return The new header.
	 */
	public JWEHeader setKeyID(final String kid) {

		return new JWEHeader(
			getAlgorithm(),
			getEncryptionMethod(),
			getType(),
			getContentType(),
			getCriticalHeaders(),
			getJWKURL(),
			getJWK(),
			getX509CertURL(),
			getX509CertThumbprint(),
			getX509CertChain(),
			kid,
			getEphemeralPublicKey(),
			getCompressionAlgorithm(),
			getAgreementPartyUInfo(),
			getAgreementPartyVInfo(),
			getPBES2Salt(),
			getPBES2Count(),
			getCustomParameters(),
			getParsedBase64URL()
		);
	}


	/**
	 * Gets the Ephemeral Public Key ({@code epk}) parameter.
	 *
	 * @return The Ephemeral Public Key parameter, {@code null} if not
	 *         specified.
	 */
	public ECKey getEphemeralPublicKey() {

		return epk;
	}


	/**
	 * Sets the Ephemeral Public Key ({@code epk}) parameter.
	 *
	 * @param epk The Ephemeral Public Key parameter, {@code null} if not 
	 *            specified.
	 *
	 * @return The new header.
	 */
	public JWEHeader setEphemeralPublicKey(final ECKey epk) {

		return new JWEHeader(
			getAlgorithm(),
			getEncryptionMethod(),
			getType(),
			getContentType(),
			getCriticalHeaders(),
			getJWKURL(),
			getJWK(),
			getX509CertURL(),
			getX509CertThumbprint(),
			getX509CertChain(),
			getKeyID(),
			epk,
			getCompressionAlgorithm(),
			getAgreementPartyUInfo(),
			getAgreementPartyVInfo(),
			getPBES2Salt(),
			getPBES2Count(),
			getCustomParameters(),
			getParsedBase64URL()
		);
	}


	/**
	 * Gets the compression algorithm ({@code zip}) parameter.
	 *
	 * @return The compression algorithm parameter, {@code null} if not
	 *         specified.
	 */
	public CompressionAlgorithm getCompressionAlgorithm() {

		return zip;
	}


	/**
	 * Sets the compression algorithm ({@code zip}) parameter.
	 *
	 * @param zip The compression algorithm parameter, {@code null} if not 
	 *            specified.
	 *
	 * @return The new header.
	 */
	public JWEHeader setCompressionAlgorithm(final CompressionAlgorithm zip) {

		return new JWEHeader(
			getAlgorithm(),
			getEncryptionMethod(),
			getType(),
			getContentType(),
			getCriticalHeaders(),
			getJWKURL(),
			getJWK(),
			getX509CertURL(),
			getX509CertThumbprint(),
			getX509CertChain(),
			getKeyID(),
			getEphemeralPublicKey(),
			zip,
			getAgreementPartyUInfo(),
			getAgreementPartyVInfo(),
			getPBES2Salt(),
			getPBES2Count(),
			getCustomParameters(),
			getParsedBase64URL()
		);
	}


	/**
	 * Gets the agreement PartyUInfo ({@code apu}) parameter.
	 *
	 * @return The agreement PartyUInfo parameter, {@code null} if not
	 *         specified.
	 */
	public Base64URL getAgreementPartyUInfo() {

		return apu;
	}


	/**
	 * Sets the agreement PartyUInfo ({@code apu}) parameter.
	 *
	 * @param apu The agreement PartyUInfo parameter, {@code null} if not
	 *            specified.
	 *
	 * @return The new header.
	 */
	public JWEHeader setAgreementPartyUInfo(final Base64URL apu) {

		return new JWEHeader(
			getAlgorithm(),
			getEncryptionMethod(),
			getType(),
			getContentType(),
			getCriticalHeaders(),
			getJWKURL(),
			getJWK(),
			getX509CertURL(),
			getX509CertThumbprint(),
			getX509CertChain(),
			getKeyID(),
			getEphemeralPublicKey(),
			getCompressionAlgorithm(),
			apu,
			getAgreementPartyVInfo(),
			getPBES2Salt(),
			getPBES2Count(),
			getCustomParameters(),
			getParsedBase64URL()
		);
	}


	/**
	 * Gets the agreement PartyVInfo ({@code apv}) parameter.
	 *
	 * @return The agreement PartyVInfo parameter, {@code null} if not
	 *         specified.
	 */
	public Base64URL getAgreementPartyVInfo() {

		return apv;
	}


	/**
	 * Sets the agreement PartyVInfo ({@code apv}) parameter.
	 *
	 * @param apv The agreement PartyVInfo parameter, {@code null} if not
	 *            specified.
	 *
	 * @return The new header.
	 */
	public JWEHeader setAgreementPartyVInfo(final Base64URL apv) {

		return new JWEHeader(
			getAlgorithm(),
			getEncryptionMethod(),
			getType(),
			getContentType(),
			getCriticalHeaders(),
			getJWKURL(),
			getJWK(),
			getX509CertURL(),
			getX509CertThumbprint(),
			getX509CertChain(),
			getKeyID(),
			getEphemeralPublicKey(),
			getCompressionAlgorithm(),
			getAgreementPartyUInfo(),
			apv,
			getPBES2Salt(),
			getPBES2Count(),
			getCustomParameters(),
			getParsedBase64URL()
		);
	}


	/**
	 * Gets the PBES2 salt ({@code p2s}) parameter.
	 *
	 * @return The PBES2 salt parameter, {@code null} if not specified.
	 */
	public Base64URL getPBES2Salt() {

		return p2s;
	}


	/**
	 * Sets the PBES2 salt ({@code p2s}) parameter.
	 *
	 * @param p2s The PBES2 salt parameter, {@code null} if not specified.
	 *
	 * @return The new header.
	 */
	public JWEHeader setPBES2Salt(final Base64URL p2s) {

		return new JWEHeader(
			getAlgorithm(),
			getEncryptionMethod(),
			getType(),
			getContentType(),
			getCriticalHeaders(),
			getJWKURL(),
			getJWK(),
			getX509CertURL(),
			getX509CertThumbprint(),
			getX509CertChain(),
			getKeyID(),
			getEphemeralPublicKey(),
			getCompressionAlgorithm(),
			getAgreementPartyUInfo(),
			getAgreementPartyVInfo(),
			p2s,
			getPBES2Count(),
			getCustomParameters(),
			getParsedBase64URL()
		);
	}


	/**
	 * Gets the PBES2 count ({@code p2c}) parameter.
	 *
	 * @return The PBES2 count parameter, zero if not specified.
	 */
	public int getPBES2Count() {

		return p2c;
	}


	/**
	 * Sets the PBES2 count ({@code p2c}) parameter.
	 *
	 * @param p2c The PBES2 count parameter, zero if not specified. Must
	 *            not be negative.
	 *
	 * @return The new header.
	 */
	public JWEHeader setPBES2Count(final int p2c) {

		if (p2c < 0)
			throw new IllegalArgumentException("The PBES2 count parameter must not be negative");

		return new JWEHeader(
			getAlgorithm(),
			getEncryptionMethod(),
			getType(),
			getContentType(),
			getCriticalHeaders(),
			getJWKURL(),
			getJWK(),
			getX509CertURL(),
			getX509CertThumbprint(),
			getX509CertChain(),
			getKeyID(),
			getEphemeralPublicKey(),
			getCompressionAlgorithm(),
			getAgreementPartyUInfo(),getAgreementPartyVInfo(),
			getPBES2Salt(),
			p2c,
			getCustomParameters(),
			getParsedBase64URL()
		);
	}


	/**
	 * Sets a custom (non-registered) parameter.
	 *
	 * @param name  The name of the custom parameter. Must not match a
	 *              registered parameter name and must not be {@code null}.
	 * @param value The value of the custom parameter, should map to a
	 *              valid JSON entity, {@code null} if not specified.
	 *
	 * @return The new header.
	 *
	 * @throws IllegalArgumentException If the specified parameter name
	 *                                  matches a registered parameter
	 *                                  name.
	 */
	public JWEHeader setCustomParameter(final String name, final Object value) {

		if (getRegisteredParameterNames().contains(name)) {
			throw new IllegalArgumentException("The parameter name \"" + name + "\" matches a registered name");
		}

		Map<String,Object> params = new HashMap<String,Object>();
		params.putAll(getCustomParameters());
		params.put(name, value);

		return new JWEHeader(
			getAlgorithm(),
			getEncryptionMethod(),
			getType(),
			getContentType(),
			getCriticalHeaders(),
			getJWKURL(),
			getJWK(),
			getX509CertURL(),
			getX509CertThumbprint(),
			getX509CertChain(),
			getKeyID(),
			getEphemeralPublicKey(),
			getCompressionAlgorithm(),
			getAgreementPartyUInfo(),getAgreementPartyVInfo(),
			getPBES2Salt(),
			getPBES2Count(),
			params,
			getParsedBase64URL()
		);
	}


	/**
	 * Sets the custom (non-registered) parameters. The values must be
	 * serialisable to a JSON entity, otherwise will be ignored.
	 *
	 * @param customParameters The custom parameters, empty map or
	 *                         {@code null} if none.
	 *
	 * @return The new header.
	 */
	public JWEHeader setCustomParameters(final Map<String,Object> customParameters) {

		return new JWEHeader(
			getAlgorithm(),
			getEncryptionMethod(),
			getType(),
			getContentType(),
			getCriticalHeaders(),
			getJWKURL(),
			getJWK(),
			getX509CertURL(),
			getX509CertThumbprint(),
			getX509CertChain(),
			getKeyID(),
			getEphemeralPublicKey(),
			getCompressionAlgorithm(),
			getAgreementPartyUInfo(),getAgreementPartyVInfo(),
			getPBES2Salt(),
			getPBES2Count(),
			customParameters,
			getParsedBase64URL()
		);
	}


	@Override
	public Set<String> getIncludedParameters() {

		Set<String> includedParameters = super.getIncludedParameters();

		if (enc != null) {
			includedParameters.add("enc");
		}

		if (epk != null) {
			includedParameters.add("epk");
		}

		if (zip != null) {
			includedParameters.add("zip");
		}

		if (apu != null) {
			includedParameters.add("apu");
		}
		
		if (apv != null) {
			includedParameters.add("apv");
		}

		if (p2s != null) {
			includedParameters.add("p2s");
		}

		if (p2c > 0) {
			includedParameters.add("p2c");
		}

		return includedParameters;
	}


	@Override
	public JSONObject toJSONObject() {

		JSONObject o = super.toJSONObject();

		if (enc != null) {
			o.put("enc", enc.toString());
		}

		if (epk != null) {
			o.put("epk", epk.toJSONObject());
		}

		if (zip != null) {
			o.put("zip", zip.toString());
		}

		if (apu != null) {
			o.put("apu", apu.toString());
		}
		
		if (apv != null) {
			o.put("apv", apv.toString());
		}

		if (p2s != null) {
			o.put("p2s", p2s.toString());
		}

		if (p2c > 0) {
			o.put("p2c", p2c);
		}

		return o;
	}


	/**
	 * Parses an encryption method ({@code enc}) parameter from the 
	 * specified JWE header JSON object.
	 *
	 * @param json The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The encryption method.
	 *
	 * @throws ParseException If the {@code enc} parameter couldn't be 
	 *                        parsed.
	 */
	private static EncryptionMethod parseEncryptionMethod(final JSONObject json)
		throws ParseException {

		return EncryptionMethod.parse(JSONObjectUtils.getString(json, "enc"));
	}


	/**
	 * Parses a JWE header from the specified JSON object.
	 *
	 * @param jsonObject The JSON object to parse. Must not be
	 *                   {@code null}.
	 *
	 * @return The JWE header.
	 *
	 * @throws ParseException If the specified JSON object doesn't
	 *                        represent a valid JWE header.
	 */
	public static JWEHeader parse(final JSONObject jsonObject)
		throws ParseException {

		return parse(jsonObject, null);
	}


	/**
	 * Parses a JWE header from the specified JSON object.
	 *
	 * @param jsonObject      The JSON object to parse. Must not be
	 *                        {@code null}.
	 * @param parsedBase64URL The original parsed Base64URL, {@code null}
	 *                        if not applicable.
	 *
	 * @return The JWE header.
	 *
	 * @throws ParseException If the specified JSON object doesn't 
	 *                        represent a valid JWE header.
	 */
	public static JWEHeader parse(final JSONObject jsonObject,
				      final Base64URL parsedBase64URL)
		throws ParseException {

		// Get the "alg" parameter
		Algorithm alg = Header.parseAlgorithm(jsonObject);

		if (! (alg instanceof JWEAlgorithm)) {
			throw new ParseException("The algorithm \"alg\" header parameter must be for encryption", 0);
		}

		// Get the "enc" parameter
		EncryptionMethod enc = parseEncryptionMethod(jsonObject);

		JOSEObjectType typ = null;
		String cty = null;
		Set<String> crit = null;
		URL jku = null;
		JWK jwk = null;
		URL x5u = null;
		Base64URL x5t = null;
		List<Base64> x5c = null;
		String kid = null;
		ECKey epk = null;
		CompressionAlgorithm zip = null;
		Base64URL apu = null;
		Base64URL apv = null;
		Base64URL p2s = null;
		int p2c = 0;
		Map<String,Object> customParams = new HashMap<String,Object>();

		// Parse optional + custom parameters
		for(final String name: jsonObject.keySet()) {

			if (name.equals("alg")) {
				continue; // skip
			} else if (name.equals("enc")) {
				continue; // skip
			} else if (name.equals("typ")) {
				typ = new JOSEObjectType(JSONObjectUtils.getString(jsonObject, name));
			} else if (name.equals("cty")) {
				cty = JSONObjectUtils.getString(jsonObject, name);
			} else if (name.equals("crit")) {
				crit = new HashSet<String>(JSONObjectUtils.getStringList(jsonObject, name));
			} else if (name.equals("jku")) {
				jku = JSONObjectUtils.getURL(jsonObject, name);
			} else if (name.equals("jwk")) {
				jwk = JWK.parse(JSONObjectUtils.getJSONObject(jsonObject, name));
			} else if (name.equals("x5u")) {
				x5u = JSONObjectUtils.getURL(jsonObject, name);
			} else if (name.equals("x5t")) {
				x5t = new Base64URL(JSONObjectUtils.getString(jsonObject, name));
			} else if (name.equals("x5c")) {
				x5c = X509CertChainUtils.parseX509CertChain(JSONObjectUtils.getJSONArray(jsonObject, name));
			} else if (name.equals("kid")) {
				kid = JSONObjectUtils.getString(jsonObject, name);
			} else if (name.equals("epk")) {
				epk = ECKey.parse(JSONObjectUtils.getJSONObject(jsonObject, name));
			} else if (name.equals("zip")) {
				zip = new CompressionAlgorithm(JSONObjectUtils.getString(jsonObject, name));
			} else if (name.equals("apu")) {
				apu = new Base64URL(JSONObjectUtils.getString(jsonObject, name));
			} else if (name.equals("apv")) {
				apv = new Base64URL(JSONObjectUtils.getString(jsonObject, name));
			} else if (name.equals("p2s")) {
				p2s = new Base64URL(JSONObjectUtils.getString(jsonObject, name));
			} else if (name.equals("p2c")) {
				p2c = JSONObjectUtils.getInt(jsonObject, name);
			} else {
				customParams.put(name, jsonObject.get(name));
			}
		}

		return new JWEHeader(
			alg, enc, typ, cty, crit, jku, jwk, x5u, x5t, x5c, kid,
			epk, zip, apu, apv, p2s, p2c,
			customParams, parsedBase64URL
		);
	}


	/**
	 * Parses a JWE header from the specified JSON object string.
	 *
	 * @param jsonString The JSON object string to parse. Must not be {@code null}.
	 *
	 * @return The JWE header.
	 *
	 * @throws ParseException If the specified JSON object string doesn't 
	 *                        represent a valid JWE header.
	 */
	public static JWEHeader parse(final String jsonString)
		throws ParseException {

		return parse(JSONObjectUtils.parseJSONObject(jsonString), null);
	}


	/**
	 * Parses a JWE header from the specified JSON object string.
	 *
	 * @param jsonString      The JSON string to parse. Must not be
	 *                        {@code null}.
	 * @param parsedBase64URL The original parsed Base64URL, {@code null}
	 *                        if not applicable.
	 *
	 * @return The JWE header.
	 *
	 * @throws ParseException If the specified JSON object string doesn't
	 *                        represent a valid JWE header.
	 */
	public static JWEHeader parse(final String jsonString,
				      final Base64URL parsedBase64URL)
		throws ParseException {

		return parse(JSONObjectUtils.parseJSONObject(jsonString), parsedBase64URL);
	}


	/**
	 * Parses a JWE header from the specified Base64URL.
	 *
	 * @param base64URL The Base64URL to parse. Must not be {@code null}.
	 *
	 * @return The JWE header.
	 *
	 * @throws ParseException If the specified Base64URL doesn't represent
	 *                        a valid JWE header.
	 */
	public static JWEHeader parse(final Base64URL base64URL)
		throws ParseException {

		return parse(base64URL.decodeToString(), base64URL);
	}
}
