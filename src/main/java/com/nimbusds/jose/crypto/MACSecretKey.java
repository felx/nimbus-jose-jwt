package com.nimbusds.jose.crypto;


import java.util.Arrays;
import javax.crypto.SecretKey;

import net.jcip.annotations.Immutable;


/**
 * MAC secret key.
 */
@Immutable
final class MACSecretKey implements SecretKey {


	/**
	 * The key bytes.
	 */
	private final byte[] bytes;


	/**
	 * Creates a new MAC secret key.
	 *
	 * @param bytes The key bytes. Must not be {@code null} or zero size.
	 */
	public MACSecretKey(final byte[] bytes) {

		if (bytes == null || bytes.length == 0) {
			throw new IllegalArgumentException("The MAC secret key bytes must not be null or zero size");
		}

		this.bytes = bytes;
	}


	@Override
	public String getAlgorithm() {

		return "MAC";
	}


	@Override
	public String getFormat() {

		return null;
	}


	@Override
	public byte[] getEncoded() {

		return bytes;
	}


	@Override
	public boolean equals(Object o) {

		if (this == o) return true;
		if (!(o instanceof MACSecretKey)) return false;
		MACSecretKey that = (MACSecretKey) o;
		return Arrays.equals(bytes, that.bytes);

	}


	@Override
	public int hashCode() {

		return Arrays.hashCode(bytes);
	}
}
