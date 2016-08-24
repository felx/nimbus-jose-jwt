package com.nimbusds.jose.util;


import java.util.Arrays;


/**
 * Array utilities.
 */
public class ArrayUtils {
	
	
	/**
	 * Concatenates the specified arrays.
	 *
	 * @param first The first array. Must not be {@code null}.
	 * @param rest  The remaining arrays.
	 * @param <T>   The array type.
	 *
	 * @return The resulting array.
	 */
	public static <T> T[] concat(final T[] first, final T[]... rest) {
		int totalLength = first.length;
		for (T[] array : rest) {
			totalLength += array.length;
		}
		T[] result = Arrays.copyOf(first, totalLength);
		int offset = first.length;
		for (T[] array : rest) {
			System.arraycopy(array, 0, result, offset, array.length);
			offset += array.length;
		}
		return result;
	}
	
	
	/**
	 * Prevents public instantiation.
	 */
	private ArrayUtils() {
	}
}
