package com.nimbusds.jose;


import java.net.MalformedURLException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;

import com.nimbusds.util.Base64URL;


/**
 * JSON Web Encryption (JWE) header.
 *
 * <p>Supports all reserved header parameters of the JWE specification:
 *
 * <ul>
 *     <li>alg
 *     <li>enc
 *     <li>int
 *     <li>kdf
 *     <li>iv
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
 * </ul>
 *
 * <p>The header may also carry {@link #setCustomParameters custom parameters};
 * these will be serialised and parsed along the reserved ones.
 *
 * <p>Example header:
 *
 * <pre>
 * { 
 *   "alg":"RSA1_5",
 *   "enc":"A128CBC",
 *   "int":"HS256",
 *   "iv":"AxY8DCtDaGlsbGljb3RoZQ"
 * }
 * </pre>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-09-19)
 */
public class JWEHeader extends CommonSEHeader implements ReadOnlyJWEHeader {


	/**
	 * The encryption method ({@code enc}) parameter.
	 */
	private EncryptionMethod enc;
	
	
	/**
	 * The integrity algorithm ({@code int}) parameter.
	 */
	private JWSAlgorithm ia;
	
	
	/**
	 * The key derivation function ({@code kdf}) parameter.
	 */
	private KeyDerivationFunction kdf;
	
	
	/**
	 * The initialisation vector ({@code iv}) parameter.
	 */
	private Base64URL iv;
	
	
	/**
	 * The ephemeral public key ({@code epk}) parameter.
	 */
	private ECKey epk;
	
	
	/**
	 * The compression algorithm ({@code zip}) parameter.
	 */
	private CompressionAlgorithm zip;
	
	
	/**
	 * Creates a new JSON Web Encryption (JWE) header.
	 *
	 * @param alg The JWE algorithm parameter. Must not be {@code null}.
	 * @param enc The encryption method parameter. Must not be {@code null}.
	 */
	public JWEHeader(final JWEAlgorithm alg, final EncryptionMethod enc) {
	
		super(alg);
		
		if (enc == null)
			throw new IllegalArgumentException("The encryption method \"enc\" parameter must not be null");
		
		this.enc = enc;
	}
	
	
	@Override
	public JWEAlgorithm getAlgorithm() {
	
		return (JWEAlgorithm)alg;
	}
	
	
	@Override
	public EncryptionMethod getEncryptionMethod() {
	
		return enc;
	}
	
	
	@Override
	public JWSAlgorithm getIntegrityAlgorithm() {
	
		return ia;
	}
	
	
	/**
	 * Sets the integrity algorithm ({@code int}) parameter.
	 *
	 * @param ia The integrity algorithm parameter, {@code null} if not 
	 *           specified.
	 */
	public void setIntegrityAlgorithm(final JWSAlgorithm ia) {
	
		this.ia = ia;
	}
	
	
	@Override
	public KeyDerivationFunction getKeyDerivationFunction() {
	
		return kdf;
	}
	
	
	/**
	 * Sets the key derivation function ({@code kdf}) parameter.
	 *
	 * @param kdf The key derivation function, {@code null} if not 
	 *            specified.
	 */
	public void setKeyDerivationFunction(final KeyDerivationFunction kdf) {
	
		this.kdf = kdf;
	}
	
	
	@Override
	public Base64URL getInitializationVector() {
	
		return iv;
	}
	
	
	/**
	 * Sets the initialisation vector ({@code iv}) parameter.
	 *
	 * @param iv The initialisation vector parameter, {@code null} if not 
	 *           specified.
	 */
	public void setInitializationVector(final Base64URL iv) {
	
		this.iv = iv;
	}
	
	
	@Override
	public ECKey getEphemeralPublicKey() {
	
		return epk;
	}
	
	
	/**
	 * Sets the Ephemeral Public Key ({@code epk}) parameter.
	 *
	 * @param epk The Ephemeral Public Key parameter, {@code null} if not 
	 *            specified.
	 */
	public void setEphemeralPublicKey(final ECKey epk) {
	
		this.epk = epk;
	}
	
	
	@Override
	public CompressionAlgorithm getCompressionAlgorithm() {
	
		return zip;
	}
	
	
	/**
	 * Sets the compression algorithm ({@code zip}) parameter.
	 *
	 * @param zip The compression algorithm parameter, {@code null} if not 
	 *            specified.
	 */
	public void setCompressionAlgorithm(final CompressionAlgorithm zip) {
	
		this.zip = zip;
	}
	
	
	@Override
	public JSONObject toJSONObject() {
	
		JSONObject o = super.toJSONObject();
	
		if (enc != null)
			o.put("enc", enc.toString());
		
		if (ia != null)
			o.put("int", ia.toString());
			
		if (kdf != null)
			o.put("kdf", kdf.toString());
		
		if (iv != null)
			o.put("iv", iv.toString());
		
		if (epk != null)
			o.put("epk", epk.toJSONObject());
		
		if (zip != null)
			o.put("zip", zip.toString());
		
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
		
		if (! json.containsKey("enc") || json.get("enc") == null)
			throw new ParseException("Missing encryption method \"enc\" header parameter");
		
		if (! (json.get("enc") instanceof String))
			throw new ParseException("Invalid encryption method \"enc\" header parameter: Must be string");
		
		return EncryptionMethod.parse((String)json.get("enc"));
	}
	
	
	/**
	 * Parses a JWE header from the specified JSON object.
	 *
	 * @param json The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The JWE header.
	 *
	 * @throws ParseException If the specified JSON object doesn't 
	 *                        represent a valid JWE header.
	 */
	public static JWEHeader parse(final JSONObject json)
		throws ParseException {
	
		if (json == null)
			throw new ParseException("The JSON object must not be null");
		
		
		// Get the "alg" parameter
		Algorithm alg = Header.parseAlgorithm(json);
		
		if (! (alg instanceof JWEAlgorithm))
			throw new ParseException("The algorithm \"alg\" header parameter must be for encryption");
		
		// Get the "enc" parameter
		EncryptionMethod enc = parseEncryptionMethod(json);
		
		// Create a minimal header
		JWEHeader h = new JWEHeader((JWEAlgorithm)alg, enc);
	
		// Parse optional + custom parameters
		Map<String,Object> customParameters = new HashMap<String,Object>();
		
		Iterator<Map.Entry<String,Object>> it = json.entrySet().iterator();
		
		while (it.hasNext()) {
		
			Map.Entry<String,Object> entry = it.next();
			String name = entry.getKey();
			Object value = entry.getValue();
			
			if (value == null)
				continue;
			
			try {
				if (name.equals("alg")) {
					// Skip
					continue;
				}
				else if (name.equals("enc")) {
					// Skip
					continue;
				}
				else if (name.equals("int")) {
				
					h.setIntegrityAlgorithm(JWSAlgorithm.parse((String)value));
				}
				else if (name.equals("kdf")) {
				
					h.setKeyDerivationFunction(KeyDerivationFunction.parse((String)value));
				}
				else if (name.equals("iv")) {
				
					h.setInitializationVector(new Base64URL((String)value));
				}
				else if (name.equals("epk")) {
				
					h.setEphemeralPublicKey(ECKey.parse((JSONObject)value));
				}
				else if (name.equals("zip")) {
				
					h.setCompressionAlgorithm(new CompressionAlgorithm((String)value));
				}
				else if (name.equals("typ")) {
				
					h.setType(Header.parseType(json));
				}
				else if (name.equals("cty")) {
					
					h.setContentType(Header.parseContentType(json));
				}
				else if (name.equals("jku")) {

					h.setJWKURL(new URL((String)value));
				}
				else if (name.equals("jwk")) {
				
					h.setJWK(JWK.parse((JSONObject)value));
				}
				else if (name.equals("x5u")) {

					h.setX509CertURL(new URL((String)value));
				}
				else if (name.equals("x5t")) {

					h.setX509CertThumbprint(new Base64URL((String)value));
				}
				else if (name.equals("x5c")) {
					
					h.setX509CertChain(CommonSEHeader.parseX509CertChain((JSONArray)value));
				}
				else if (name.equals("kid")) {
				
					h.setKeyID((String)value);
				}
				else {
					// Custom parameter
					customParameters.put(name, value);
				}
			
			} catch (ClassCastException e) {
			
				// All params
				throw new ParseException("Unexpected JSON type of the \"" + name + "\" header parameter", e);
				
			} catch (MalformedURLException e) {
			
				// All URL params
				throw new ParseException("Invalid URL of the \"" + name + "\" header parameter", e);
			}
		}
		
		if (! customParameters.isEmpty())
			h.setCustomParameters(customParameters);
		
		return h;
	}
	
	
	/**
	 * Parses a JWE header from the specified JSON string.
	 *
	 * @param s The JSON string to parse. Must not be {@code null}.
	 *
	 * @return The JWE header.
	 *
	 * @throws ParseException If the specified JSON object string doesn't 
	 *                        represent a valid JWE header.
	 */
	public static JWEHeader parse(final String s)
		throws ParseException {
		
		JSONObject json = Header.parseHeaderJSON(s);
		
		return parse(json);
	}
	
	
	/**
	 * Parses a JWE header from the specified Base64URL.
	 *
	 * @param base64URL The Base64URL to parse. Must not be {@code null}.
	 *
	 * @return The JWE header.
	 *
	 * @throws ParseException If the specified Base64URL doesn't represent a 
	 *                        valid JWE header.
	 */
	public static JWEHeader parse(final Base64URL base64URL)
		throws ParseException {
		
		if (base64URL == null)
			throw new ParseException("The Base64URL must not be null");
			
		return parse(base64URL.decodeToString());
	}
}
