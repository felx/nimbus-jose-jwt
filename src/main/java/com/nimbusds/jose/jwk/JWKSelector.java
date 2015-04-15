package com.nimbusds.jose.jwk;


import java.util.*;

import net.jcip.annotations.Immutable;


/**
 * Selects (filters) one or more JSON Web Keys (JWKs) from a JWK set.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-04-15)
 */
@Immutable
public final class JWKSelector {


	/**
	 * The JWK matcher.
	 */
	private final JWKMatcher matcher;



	public JWKSelector(final JWKMatcher matcher) {

		if (matcher == null) {
			throw new IllegalArgumentException("The JWK matcher must not be null");
		}

		this.matcher = matcher;
	}


	/**
	 * Returns the JWK matcher.
	 *
	 * @return The JWK matcher.
	 */
	public JWKMatcher getMatcher() {

		return matcher;
	}


	/**
	 * Selects the keys from the specified JWK set according to the
	 * matcher's criteria.
	 *
	 * @param jwkSet The JWK set. May be {@code null}.
	 *
	 * @return The selected keys, ordered by their position in the JWK set,
	 *         empty list if none were matched or the JWK is {@code null}.
	 */
	public List<JWK> select(final JWKSet jwkSet) {

		List<JWK> selectedKeys = new LinkedList<>();

		if (jwkSet == null)
			return selectedKeys;

		for (JWK key: jwkSet.getKeys()) {

			if (matcher.matches(key)) {
				selectedKeys.add(key);
			}
		}

		return selectedKeys;
	}
}
