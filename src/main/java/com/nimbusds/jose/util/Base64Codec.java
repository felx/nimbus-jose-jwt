package com.nimbusds.jose.util;


import java.util.Arrays;


/**
 * Base 64 and base 64 URL-safe encoder and decoder.
 *
 * <p>Based on Mikael Grev's MiG base 64 encoder / decoder, with modifications
 * to support URL-safe encoding and decoding.
 *
 * <p>Original licence:
 *
 * <pre>
 * Licence (BSD):
 *
 * Copyright (c) 2004, Mikael Grev, MiG InfoCom AB. (base64 @ miginfocom . com)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer. Redistributions in binary
 * form must reproduce the above copyright notice, this list of conditions and
 * the following disclaimer in the documentation and/or other materials provided
 * with the distribution. Neither the name of the MiG InfoCom AB nor the names
 * of its contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 * </pre>
 *
 * @author Mikael Grev
 * @author Jaap Beetstra
 * @author Vladimir Dzhuvinov
 */
final class Base64Codec {


	/**
	 * The base 64 characters.
	 */
	private static final char[] CA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray();


	/**
	 * The base 64 URL safe characters.
	 */
	private static final char[] CA_URL_SAFE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".toCharArray();


	/**
	 * Maps base 64 characters to their respective byte values.
	 */
	private static final int[] IA = new int[256];


	static {
		Arrays.fill(IA, -1);
		for (int i = 0, iS = CA.length; i < iS; i++)
			IA[CA[i]] = i;
		IA['='] = 0;
	}


	/**
	 * Computes the base 64 encoded character length for the specified
	 * input byte length.
	 *
	 * @param inputLength The input byte length.
	 * @param urlSafe     {@code true} for URL-safe encoding.
	 *
	 * @return The base 64 encoded character length.
	 */
	public static int computeEncodedLength(final int inputLength, final boolean urlSafe) {

		if (inputLength == 0) {
			return 0;
		}

		if (urlSafe) {

			// Compute the number of complete quads (4-char blocks)
			int fullQuadLength = (inputLength / 3) << 2;

			// Compute the remaining bytes at the end
			int remainder = inputLength % 3;

			// Compute the total
			return remainder == 0 ? fullQuadLength : fullQuadLength + remainder + 1;
		} else {
			// Original Mig code
			return ((inputLength - 1) / 3 + 1) << 2;
		}
	}


	/**
	 * Normalises a base 64 encoded string by ensuring any URL-safe
	 * characters are replaced with their regular base64 representation and
	 * any truncated '=' padding is restored.
	 *
	 * @param value The base 64 or base 64 URL-safe encoded string. Must
	 *              not be {@code null}.
	 *
	 * @return The normalised base 64 encoded string.
	 */
	public static String normalizeEncodedString(final String value) {

		int len = value.length();

		// Restore padding if missing
		int padLength = len % 4 == 0 ? 0 : 4 - (len % 4);

		char[] chars = new char[len + padLength];

		value.getChars(0, len, chars, 0);

		for (int i = 0; i < padLength; i++) {
			chars[len + i] = '=';
		}

		// Replace URL-safe chars
		for (int i = 0; i < len; i++) {
			if (chars[i] == '_') {
				chars[i] = '/';
			} else if (chars[i] == '-') {
				chars[i] = '+';
			}
		}

		return new String(chars);
	}


	/**
	 * Encodes a byte array into a base 64 encoded character array.
	 *
	 * @param sArr    The bytes to convert. If {@code null} or length 0 an
	 *                empty array will be returned.
	 * @param urlSafe If {@code true} to apply URL-safe encoding (padding
	 *                still included and not to spec).
	 *
	 * @return The base 64 encoded character array. Never {@code null}.
	 */
	public static char[] encodeToChar(final byte[] sArr, final boolean urlSafe) {

		// Check special case
		int sLen = sArr != null ? sArr.length : 0;

		if (sLen == 0) {
			return new char[0];
		}

		int eLen = (sLen / 3) * 3;                      // Length of even 24-bits.
		int dLen = computeEncodedLength(sLen, urlSafe); // Returned character count
		char[] out = new char[dLen];

		// Encode even 24-bits
		for (int s = 0, d = 0; s < eLen; ) {

			// Copy next three bytes into lower 24 bits of int, paying attention to sign
			int i = (sArr[s++] & 0xff) << 16 | (sArr[s++] & 0xff) << 8 | (sArr[s++] & 0xff);

			// Encode the int into four chars
			if (urlSafe) {
				out[d++] = CA_URL_SAFE[(i >>> 18) & 0x3f];
				out[d++] = CA_URL_SAFE[(i >>> 12) & 0x3f];
				out[d++] = CA_URL_SAFE[(i >>> 6) & 0x3f];
				out[d++] = CA_URL_SAFE[i & 0x3f];
			} else {
				out[d++] = CA[(i >>> 18) & 0x3f];
				out[d++] = CA[(i >>> 12) & 0x3f];
				out[d++] = CA[(i >>> 6) & 0x3f];
				out[d++] = CA[i & 0x3f];
			}
		}

		// Pad and encode last bits if source isn't even 24 bits
		// according to URL-safe switch
		int left = sLen - eLen; // 0 - 2.
		if (left > 0) {
			// Prepare the int
			int i = ((sArr[eLen] & 0xff) << 10) | (left == 2 ? ((sArr[sLen - 1] & 0xff) << 2) : 0);

			// Set last four chars
			if (urlSafe) {

				if (left == 2) {
					out[dLen - 3] = CA_URL_SAFE[i >> 12];
					out[dLen - 2] = CA_URL_SAFE[(i >>> 6) & 0x3f];
					out[dLen - 1] = CA_URL_SAFE[i & 0x3f];
				} else {
					out[dLen - 2] = CA_URL_SAFE[i >> 12];
					out[dLen - 1] = CA_URL_SAFE[(i >>> 6) & 0x3f];
				}
			} else {
				// Original Mig code with padding
				out[dLen - 4] = CA[i >> 12];
				out[dLen - 3] = CA[(i >>> 6) & 0x3f];
				out[dLen - 2] = left == 2 ? CA[i & 0x3f] : '=';
				out[dLen - 1] = '=';
			}
		}

		return out;
	}


	/**
	 * Encodes a byte array into a base 64 encoded string.
	 *
	 * @param sArr    The bytes to convert. If {@code null} or length 0 an
	 *                empty array will be returned.
	 * @param urlSafe If {@code true} to apply URL-safe encoding (padding
	 *                still included and not to spec).
	 *
	 * @return The base 64 encoded string. Never {@code null}.
	 */
	public final static String encodeToString(byte[] sArr, final boolean urlSafe) {

		// Reuse char[] since we can't create a String incrementally
		// and StringBuffer/Builder would be slower
		return new String(encodeToChar(sArr, urlSafe));
	}


	/**
	 * Decodes a base 64 or base 64 URL-safe encoded string. May contain
	 * line separators. Any illegal characters are ignored.
	 *
	 * @param str The base 64 or base 64 URL-safe encoded string. May be
	 *            empty or {@code null}.
	 *
	 * @return The decoded byte array, empty if the input base 64 encoded
	 *         string is empty, {@code null} or corrupted.
	 */
	public final static byte[] decode(final String str) {

		// Check special case
		if (str == null || str.isEmpty()) {
			return new byte[0];
		}

		String nStr = normalizeEncodedString(str);

		int sLen = nStr.length();

		// Count illegal characters (including '\r', '\n') to determine
		// the size of the byte array to return
		int sepCnt = 0; // Number of separator and illegal characters
		for (int i = 0; i < sLen; i++) {

			if (IA[nStr.charAt(i)] < 0) {
				sepCnt++;
			}
		}

		// Ensure the legal chars (including '=' padding) are dividable
		// by 4 as specified in RFC 2045.
		if ((sLen - sepCnt) % 4 != 0) {
			// The string is corrupted
			return new byte[0];
		}

		// Count '=' at end
		int pad = 0;

		for (int i = sLen; i > 1 && IA[nStr.charAt(--i)] <= 0; ) {
			if (nStr.charAt(i) == '=') {
				pad++;
			}
		}

		int len = ((sLen - sepCnt) * 6 >> 3) - pad;

		// Preallocate byte[] of final length
		byte[] dArr = new byte[len];

		for (int s = 0, d = 0; d < len; ) {
			// Assemble three bytes into an int from four base 64
			// characters
			int i = 0;

			for (int j = 0; j < 4; j++) {
				// j only increased if a valid char was found
				int c = IA[nStr.charAt(s++)];
				if (c >= 0) {
					i |= c << (18 - j * 6);
				} else {
					j--;
				}
			}
			// Add the bytes
			dArr[d++] = (byte) (i >> 16);
			if (d < len) {
				dArr[d++] = (byte) (i >> 8);
				if (d < len) {
					dArr[d++] = (byte) i;
				}
			}
		}

		return dArr;
	}
}