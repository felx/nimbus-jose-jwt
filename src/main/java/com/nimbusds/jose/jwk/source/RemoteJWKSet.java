package com.nimbusds.jose.jwk.source;


import java.io.IOException;
import java.net.URL;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.Resource;
import com.nimbusds.jose.util.RestrictedResourceRetriever;
import net.jcip.annotations.ThreadSafe;


/**
 * Remote JSON Web Key (JWK) source specified by a JWK set URL. The retrieved
 * JWK set is cached to minimise network calls. The cache is updated whenever
 * the key selector tries to get a key with an unknown ID.
 *
 * @author Vladimir Dzhuvinov
 * @version 2016-04-10
 */
@ThreadSafe
public class RemoteJWKSet<C extends SecurityContext> implements JWKSource<C> {


	/**
	 * The default HTTP connect timeout for JWK set retrieval, in
	 * milliseconds. Set to 250 milliseconds.
	 */
	public static final int DEFAULT_HTTP_CONNECT_TIMEOUT = 250;


	/**
	 * The default HTTP read timeout for JWK set retrieval, in
	 * milliseconds. Set to 250 milliseconds.
	 */
	public static final int DEFAULT_HTTP_READ_TIMEOUT = 250;


	/**
	 * The default HTTP entity size limit for JWK set retrieval, in bytes.
	 * Set to 50 KBytes.
	 */
	public static final int DEFAULT_HTTP_SIZE_LIMIT = 50 * 1024;


	/**
	 * The JWK set URL.
	 */
	private final URL jwkSetURL;
	

	/**
	 * The cached JWK set.
	 */
	private final AtomicReference<JWKSet> cachedJWKSet = new AtomicReference<>();


	/**
	 * The JWK set retriever.
	 */
	private final RestrictedResourceRetriever jwkSetRetriever;


	/**
	 * Creates a new remote JWK set using the
	 * {@link DefaultResourceRetriever default HTTP resource retriever}.
	 * Starts an asynchronous thread to fetch the JWK set from the
	 * specified URL. The JWK set is cached if successfully retrieved.
	 *
	 * @param jwkSetURL The JWK set URL. Must not be {@code null}.
	 */
	public RemoteJWKSet(final URL jwkSetURL) {
		this(jwkSetURL, null);
	}


	/**
	 * Creates a new remote JWK set. Starts an asynchronous thread to
	 * fetch the JWK set from the specified URL. The JWK set is cached if
	 * successfully retrieved.
	 *
	 * @param jwkSetURL         The JWK set URL. Must not be {@code null}.
	 * @param resourceRetriever The HTTP resource retriever to use,
	 *                          {@code null} to use the
	 *                          {@link DefaultResourceRetriever default
	 *                          one}.
	 */
	public RemoteJWKSet(final URL jwkSetURL,
			    final RestrictedResourceRetriever resourceRetriever) {
		if (jwkSetURL == null) {
			throw new IllegalArgumentException("The JWK set URL must not be null");
		}
		this.jwkSetURL = jwkSetURL;

		if (resourceRetriever != null) {
			jwkSetRetriever = resourceRetriever;
		} else {
			jwkSetRetriever = new DefaultResourceRetriever(DEFAULT_HTTP_CONNECT_TIMEOUT, DEFAULT_HTTP_READ_TIMEOUT, DEFAULT_HTTP_SIZE_LIMIT);
		}

		Thread t = new Thread() {
			public void run() {
				updateJWKSetFromURL();
			}
		};
		t.setName("initial-jwk-set-retriever["+ jwkSetURL +"]");
		t.start();
	}


	/**
	 * Updates the cached JWK set from the configured URL.
	 *
	 * @return The updated JWK set, {@code null} if retrieval failed.
	 */
	private JWKSet updateJWKSetFromURL() {
		JWKSet jwkSet;
		try {
			Resource res = jwkSetRetriever.retrieveResource(jwkSetURL);
			jwkSet = JWKSet.parse(res.getContent());
		} catch (IOException | java.text.ParseException e) {
			return null;
		}
		cachedJWKSet.set(jwkSet);
		return jwkSet;
	}


	/**
	 * Returns the JWK set URL.
	 *
	 * @return The JWK set URL.
	 */
	public URL getJWKSetURL() {
		return jwkSetURL;
	}


	/**
	 * Returns the HTTP resource retriever.
	 *
	 * @return The HTTP resource retriever.
	 */
	public RestrictedResourceRetriever getResourceRetriever() {

		return jwkSetRetriever;
	}


	/**
	 * Returns the cached JWK set.
	 *
	 * @return The cached JWK set, {@code null} if none.
	 */
	public JWKSet getJWKSet() {
		JWKSet jwkSet = cachedJWKSet.get();
		if (jwkSet != null) {
			return jwkSet;
		}
		return updateJWKSetFromURL();
	}


	/**
	 * Returns the first specified key ID (kid) for a JWK matcher.
	 *
	 * @param jwkMatcher The JWK matcher. Must not be {@code null}.
	 *
	 * @return The first key ID, {@code null} if none.
	 */
	protected static String getFirstSpecifiedKeyID(final JWKMatcher jwkMatcher) {

		Set<String> keyIDs = jwkMatcher.getKeyIDs();

		if (keyIDs == null || keyIDs.isEmpty()) {
			return null;
		}

		for (String id: keyIDs) {
			if (id != null) {
				return id;
			}
		}
		return null; // No kid in matcher
	}


	/**
	 * {@inheritDoc} The security context is ignored.
	 */
	@Override
	public List<JWK> get(final JWKSelector jwkSelector, final C context) {

		// Get the JWK set, may necessitate a cache update
		JWKSet jwkSet = getJWKSet();
		if (jwkSet == null) {
			// Retrieval has failed
			return Collections.emptyList();
		}
		List<JWK> matches = jwkSelector.select(jwkSet);

		if (! matches.isEmpty()) {
			// Success
			return matches;
		}

		// Refresh the JWK set if the sought key ID is not in the cached JWK set
		String soughtKeyID = getFirstSpecifiedKeyID(jwkSelector.getMatcher());
		if (soughtKeyID == null) {
			// No key ID specified, return no matches
			return matches;
		}
		if (jwkSet.getKeyByKeyId(soughtKeyID) != null) {
			// The key ID exists in the cached JWK set, matching
			// failed for some other reason, return no matches
			return matches;
		}
		// Make new HTTP GET to the JWK set URL
		jwkSet = updateJWKSetFromURL();
		if (jwkSet == null) {
			// Retrieval has failed
			return null;
		}
		// Repeat select, return final result (success or no matches)
		return jwkSelector.select(jwkSet);
	}
}
