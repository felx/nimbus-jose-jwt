package com.nimbusds.jose.util;


/**
 * Integer utilities.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-05-12)
 */
public class IntegerUtils {


	/**
	 * Returns a four byte array representation of the specified integer.
	 *
	 * @param intValue The integer to be converted.
	 *
	 * @return The byte array representation of the integer.
	 */
	public static byte[] toBytes(int intValue) {

		byte[] res = new byte[4];
		res[0] = (byte) (intValue >>> 24);
		res[1] = (byte) ((intValue >>> 16) & 0xFF);
		res[2] = (byte) ((intValue >>> 8) & 0xFF);
		res[3] = (byte) (intValue & 0xFF);
		return res;
	}


	/**
	 * Prevents public instantiation.
	 */
	private IntegerUtils() {

	}
}
