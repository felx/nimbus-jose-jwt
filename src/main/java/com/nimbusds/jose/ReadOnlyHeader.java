package com.nimbusds.jose;


import java.util.Map;
import java.util.Set;

import net.minidev.json.JSONObject;

import com.nimbusds.jose.util.Base64URL;


/**
 * Read-only view of a {@link Header header}.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-04-15)
 */
public interface ReadOnlyHeader {


	/**
	 * Gets the algorithm ({@code alg}) parameter.
	 *
	 * @return The algorithm parameter.
	 */
	public Algorithm getAlgorithm();


	/**
	 * Gets the type ({@code typ}) parameter.
	 *
	 * @return The type parameter, {@code null} if not specified.
	 */
	public JOSEObjectType getType();


	/**
	 * Gets the content type ({@code cty}) parameter.
	 *
	 * @return The content type parameter, {@code null} if not specified.
	 */
	public String getContentType();


	/**
	 * Gets a custom (non-reserved) parameter.
	 *
	 * @param name The name of the custom parameter. Must not be 
	 *             {@code null}.
	 *
	 * @return The custom parameter, {@code null} if not specified.
	 */
	public Object getCustomParameter(final String name);


	/**
	 * Gets the custom (non-reserved) parameters.
	 *
	 * @return The custom parameters, as a unmodifiable map, empty map if 
	 *         none.
	 */
	public Map<String,Object> getCustomParameters();


	/**
	 * Gets the names of all included parameters (reserved and custom) in 
	 * the header instance.
	 *
	 * @return The included parameters.
	 */
	public Set<String> getIncludedParameters();


	/**
	 * Returns a JSON object representation of the header. All custom
	 * parameters are included if they serialise to a JSON entity and 
	 * their names don't conflict with the reserved ones.
	 *
	 * @return The JSON object representation of the header.
	 */
	public JSONObject toJSONObject();


	/**
	 * Returns a JSON string representation of the header. All custom
	 * parameters will be included if they serialise to a JSON entity and 
	 * their names don't conflict with the reserved ones.
	 *
	 * @return The JSON string representation of the header.
	 */
	public String toString();


	/**
	 * Returns a Base64URL representation of the header. If the header was
	 * parsed always returns the original Base64URL (required for JWS
	 * validation and authenticated JWE decryption).
	 *
	 * @return The original parsed Base64URL representation of the header,
	 *         or a new Base64URL representation if the header was created
	 *         from scratch.
	 */
	public Base64URL toBase64URL();
}
