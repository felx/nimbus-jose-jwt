package com.nimbusds.jose.jwk.source;


import javax.crypto.SecretKey;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.proc.SecurityContext;
import net.jcip.annotations.Immutable;


/**
 * JSON Web Key (JWK) source backed by an immutable secret.
 *
 * @author Vladimir Dzhuvinov
 * @version 2016-04-10
 */
@Immutable
public class ImmutableSecret<C extends SecurityContext> extends ImmutableJWKSet<C> {
	

	/**
	 * Creates a new JSON Web Key (JWK) source backed by an immutable
	 * secret.
	 *
	 * @param secret The secret. Must not be empty or {@code null}.
	 */
	public ImmutableSecret(final byte[] secret) {

		super(new JWKSet(new OctetSequenceKey.Builder(secret).build()));
	}


	/**
	 * Creates a new JSON Web Key (JWK) source backed by an immutable
	 * secret key.
	 *
	 * @param secretKey The secret key. Must not be {@code null}.
	 */
	public ImmutableSecret(final SecretKey secretKey) {

		super(new JWKSet(new OctetSequenceKey.Builder(secretKey).build()));
	}


	/**
	 * Returns the secret.
	 *
	 * @return The secret.
	 */
	public byte[] getSecret() {

		return ((OctetSequenceKey) getJWKSet().getKeys().get(0)).toByteArray();
	}


	/**
	 * Returns the secret key.
	 *
	 * @return The secret key.
	 */
	public SecretKey getSecretKey() {

		return ((OctetSequenceKey) getJWKSet().getKeys().get(0)).toSecretKey();
	}
}
