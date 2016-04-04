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
	 * The base 64 URL-safe characters.
	 */
	private static final char[] CA_URL_SAFE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".toCharArray();


	/**
	 * Maps base 64 characters to their respective byte values.
	 */
	private static final int[] IA = new int[256];


	/**
	 * Maps base 64 URL-safe characters to their respective byte values.
	 */
	private static final int[] IA_URL_SAFE = new int[256];


	static {
		// Regular map
		Arrays.fill(IA, -1);
		for (int i = 0, iS = CA.length; i < iS; i++) {
			IA[CA[i]] = i;
		}
		IA['='] = 0;

		// URL-safe map
		Arrays.fill(IA_URL_SAFE, -1);
		for (int i = 0, iS = CA_URL_SAFE.length; i < iS; i++) {
			IA_URL_SAFE[CA_URL_SAFE[i]] = i;
		}
		IA_URL_SAFE['='] = 0;
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
	 * @param b64String The base 64 or base 64 URL-safe encoded string.
	 *                  Must not be {@code null}.
	 *
	 * @return The normalised base 64 encoded string.
	 */
	public static String normalizeEncodedString(final String b64String) {

		final int inputLen = b64String.length();

		// Compute missing padding, taking illegal chars into account
		final int legalLen = inputLen - countIllegalChars(b64String);
		final int padLength = legalLen % 4 == 0 ? 0 : 4 - (legalLen % 4);

		// Create output array
		char[] chars = new char[inputLen + padLength];

		// Copy chars into output array
		b64String.getChars(0, inputLen, chars, 0);

		// Append padding chars if required
		for (int i = 0; i < padLength; i++) {
			chars[inputLen + i] = '=';
		}

		// Replace URL-safe chars
		for (int i = 0; i < inputLen; i++) {
			if (chars[i] == '_') {
				chars[i] = '/';
			} else if (chars[i] == '-') {
				chars[i] = '+';
			}
		}

		return new String(chars);
	}


	/**
	 * Counts the illegal / separator characters in the specified base 64
	 * or base 64 URL-safe encoded string.
	 *
	 * @param b64String The base 64 or base 64 URL-safe encoded string.
	 *                  Must not be {@code null}.
	 *
	 * @return The illegal character count, zero if none.
	 */
	public static int countIllegalChars(final String b64String) {

		// Number of separator and illegal characters
		int illegalCharCount = 0;

		for (int i = 0; i < b64String.length(); i++) {

			final char c = b64String.charAt(i);

			if (IA[c] == -1 && IA_URL_SAFE[c] == -1) {
				illegalCharCount++;
			}
		}

		return illegalCharCount;
	}


	/**
	 * Encodes a byte array into a base 64 encoded character array.
	 *
	 * @param byteArray The bytes to convert. If {@code null} or length 0
	 *                  an empty array will be returned.
	 * @param urlSafe   If {@code true} to apply URL-safe encoding (padding
	 *                  still included and not to spec).
	 *
	 * @return The base 64 encoded character array. Never {@code null}.
	 */
	public static char[] encodeToChar(final byte[] byteArray, final boolean urlSafe) {

		// Check special case
		int sLen = byteArray != null ? byteArray.length : 0;

		if (sLen == 0) {
			return new char[0];
		}

		int eLen = (sLen / 3) * 3;                      // Length of even 24-bits.
		int dLen = computeEncodedLength(sLen, urlSafe); // Returned character count
		char[] out = new char[dLen];

		// Encode even 24-bits
		for (int s = 0, d = 0; s < eLen; ) {

			// Copy next three bytes into lower 24 bits of int, paying attention to sign
			int i = (byteArray[s++] & 0xff) << 16 | (byteArray[s++] & 0xff) << 8 | (byteArray[s++] & 0xff);

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
			int i = ((byteArray[eLen] & 0xff) << 10) | (left == 2 ? ((byteArray[sLen - 1] & 0xff) << 2) : 0);

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
	 * @param byteArray The bytes to convert. If {@code null} or length 0
	 *                  an empty array will be returned.
	 * @param urlSafe   If {@code true} to apply URL-safe encoding (padding
	 *                  still included and not to spec).
	 *
	 * @return The base 64 encoded string. Never {@code null}.
	 */
	public static String encodeToString(byte[] byteArray, final boolean urlSafe) {

		// Reuse char[] since we can't create a String incrementally
		// and StringBuffer/Builder would be slower
		return new String(encodeToChar(byteArray, urlSafe));
	}


	/**
	 * Decodes a base 64 or base 64 URL-safe encoded string. May contain
	 * line separators. Any illegal characters are ignored.
	 *
	 * @param b64String The base 64 or base 64 URL-safe encoded string. May
	 *                  be empty or {@code null}.
	 *
	 * @return The decoded byte array, empty if the input base 64 encoded
	 *         string is empty, {@code null} or corrupted.
	 */
	public static byte[] decode(final String b64String) {

		// Check special case
		if (b64String == null || b64String.isEmpty()) {
			return new byte[0];
		}

		final String nStr = normalizeEncodedString(b64String);

		final int sLen = nStr.length();

		// Count illegal characters (including '\r', '\n') to determine
		// the size of the byte array to return
		final int sepCnt = countIllegalChars(nStr);

		// Ensure the legal chars (including '=' padding) divide by 4 (RFC 2045)
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