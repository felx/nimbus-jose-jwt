package com.nimbusds.jose.util;


import java.io.IOException;
import java.net.URL;


/**
 * Retriever of resources specified by URL.
 */
public interface ResourceRetriever {


	/**
	 * Retrieves the resource from the specified HTTP(S) URL.
	 *
	 * @param url The URL of the resource. Its scheme must be HTTP or
	 *            HTTPS. Must not be {@code null}.
	 *
	 * @return The retrieved resource.
	 *
	 * @throws IOException If the HTTP connection to the specified URL
	 *                     failed or the resource couldn't be retrieved.
	 */
	Resource retrieveResource(final URL url)
		throws IOException;
}