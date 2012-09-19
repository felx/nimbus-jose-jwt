package com.nimbusds.jose;


import java.util.Map;

import net.minidev.json.JSONObject;


/**
 * Read-only view of a {@link Header header}.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-09-19)
 */
public interface ReadOnlyHeader {


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
	 * Gets the custom (non-reserved) parameters.
	 *
	 * @return The custom parameters, empty map if none.
	 */
	public Map<String,Object> getCustomParameters();
	
	
	/**
	 * Returns a JSON object representation of the header. All custom
	 * parameters are included if they serialise to a JSON entity and 
	 * their names don't conflict with the reserved ones.
	 *
	 * @return The JSON object representation of the header.
	 */
	public JSONObject toJSONObject();
}
