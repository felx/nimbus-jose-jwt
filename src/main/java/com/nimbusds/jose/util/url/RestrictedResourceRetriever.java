package com.nimbusds.jose.util.url;


/**
 * Retriever of resources specified by URL which permits setting of HTTP
 * connect and read timeouts as well as a size limit.
 */
public interface RestrictedResourceRetriever extends ResourceRetriever {
	

	/**
	 * Gets the HTTP connect timeout.
	 *
	 * @return The HTTP connect timeout, in milliseconds, zero for
	 *         infinite.
	 */
	int getConnectTimeout();


	/**
	 * Sets the HTTP connect timeout.
	 *
	 * @param connectTimeoutMs The HTTP connect timeout, in milliseconds,
	 *                         zero for infinite. Must not be negative.
	 */
	void setConnectTimeout(final int connectTimeoutMs);


	/**
	 * Gets the HTTP read timeout.
	 *
	 * @return The HTTP read timeout, in milliseconds, zero for infinite.
	 */
	int getReadTimeout();


	/**
	 * Sets the HTTP read timeout.
	 *
	 * @param readTimeoutMs The HTTP read timeout, in milliseconds, zero
	 *                      for infinite. Must not be negative.
	 */
	void setReadTimeout(final int readTimeoutMs);


	/**
	 * Gets the HTTP entity size limit.
	 *
	 * @return The HTTP entity size limit, in bytes, zero for infinite.
	 */
	int getSizeLimit();


	/**
	 * Sets the HTTP entity size limit.
	 *
	 * @param sizeLimitBytes The HTTP entity size limit, in bytes, zero for
	 *                       infinite. Must not be negative.
	 */
	void setSizeLimit(int sizeLimitBytes);
}
