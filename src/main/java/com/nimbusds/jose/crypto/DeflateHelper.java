package com.nimbusds.jose.crypto;


import com.nimbusds.jose.CompressionAlgorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.ReadOnlyJWEHeader;
import com.nimbusds.jose.util.DeflateUtils;


/**
 * Deflate (RFC 1951) helper methods, intended for use by JWE encrypters and
 * decrypters.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-04-16)
 */
class DeflateHelper {


	/**
	 * Applies compression to the specified plain text if requested.
	 *
	 * @param readOnlyJWEHeader The JWE header. Must not be {@code null}.
	 * @param bytes             The plain text bytes. Must not be 
	 *                          {@code null}.
	 *
	 * @return The bytes to encrypt.
	 *
	 * @throws JOSEException If compression failed or the requested 
	 *                       compression algorithm is not supported.
	 */
	public static byte[] applyCompression(final ReadOnlyJWEHeader readOnlyJWEHeader, final byte[] bytes)
		throws JOSEException {

		CompressionAlgorithm compressionAlg = readOnlyJWEHeader.getCompressionAlgorithm();

		if (compressionAlg == null) {

			return bytes;

		} else if (compressionAlg.equals(CompressionAlgorithm.DEF)) {

			try {
				return DeflateUtils.compress(bytes);

			} catch (Exception e) {

				throw new JOSEException("Couldn't compress plain text: " + e.getMessage(), e);
			}

		} else {

			throw new JOSEException("Unsupported compression algorithm: " + compressionAlg);
		}
	}


	/**
	 * Applies decompression to the specified plain text if requested.
	 *
	 * @param readOnlyJWEHeader The JWE header. Must not be {@code null}.
	 * @param bytes             The plain text bytes. Must not be 
	 *                          {@code null}.
	 *
	 * @return The output bytes, decompressed if requested.
	 *
	 * @throws JOSEException If decompression failed or the requested 
	 *                       compression algorithm is not supported.
	 */
	public static byte[] applyDecompression(final ReadOnlyJWEHeader readOnlyJWEHeader, final byte[] bytes)
		throws JOSEException {

		CompressionAlgorithm compressionAlg = readOnlyJWEHeader.getCompressionAlgorithm();

		if (compressionAlg == null) {

			return bytes;

		} else if (compressionAlg.equals(CompressionAlgorithm.DEF)) {

			try {
				return DeflateUtils.decompress(bytes);

			} catch (Exception e) {

				throw new JOSEException("Couldn't decompress plain text: " + e.getMessage(), e);
			}

		} else {

			throw new JOSEException("Unsupported compression algorithm: " + compressionAlg);
		}
	}
}