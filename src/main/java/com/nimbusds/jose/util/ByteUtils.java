package com.nimbusds.jose.util;


import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;


/**
 * Byte utilities.
 *
 * @version $version$ (2015-04-23)
 */
public class ByteUtils {


	/**
	 * Returns a byte array representation of the specified integer.
	 *
	 * @param intValue The integer value.
	 *
	 * @return The byte array representatio.
	 */
	public static byte[] getBytes(int intValue) {

		ByteBuffer byteBuffer = ByteBuffer.allocate(4);
		byteBuffer.putInt(intValue);
		return byteBuffer.array();
	}


	/**
	 * Concatenates the specified byte arrays.
	 *
	 * @param byteArrays The byte arrays to concatenate.
	 *
	 * @return The resulting byte array.
	 */
	public static byte[] concat(byte[]... byteArrays) {

		try {
			ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

			for (byte[] bytes : byteArrays) {
				byteArrayOutputStream.write(bytes);
			}
			return byteArrayOutputStream.toByteArray();

		} catch (IOException e) {
			// Should never happen
			throw new IllegalStateException(e.getMessage(), e);
		}
	}


	/**
	 * Returns a portion of the specified byte array.
	 *
	 * @param byteArray  The byte array. Must not be {@code null}.
	 * @param beginIndex The beginning index, inclusive. Must be zero or
	 *                   positive.
	 * @param length     The length. Must be zero or positive.
	 *
	 * @return The byte array portion.
	 */
	public static byte[] subArray(byte[] byteArray, int beginIndex, int length) {

		byte[] subArray = new byte[length];
		System.arraycopy(byteArray, beginIndex, subArray, 0, subArray.length);
		return subArray;
	}
}
