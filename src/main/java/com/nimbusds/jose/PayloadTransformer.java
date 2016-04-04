package com.nimbusds.jose;


/**
 * Generic payload type transformer. Implementations should be tread-safe.
 */
public interface PayloadTransformer<T> {


	/**
	 * Transforms the specified payload into the desired type.
	 *
	 * @param payload The payload. Not {@code null}.
	 *
	 * @return The desired type.
	 */
	T transform(final Payload payload);
}
