package com.nimbusds.jose.crypto;


import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;


/**
 * Concatenation Key Derivation Function (KDF) utilities. Provides static 
 * methods to generate Content Encryption Keys (CEKs) and Content Integrity 
 * Keys (CIKs) from a Content Master Key (CMKs), as used in 
 * {@code A128CBC+HS256} and {@code A256CBC+HS512} encryption.
 *
 * <p>See draft-ietf-jose-json-web-encryption-08, appendices A.4 and A.5.
 *
 * <p>See NIST.800-56A.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-03-25)
 */
class ConcatKDF {


	/**
	 * The four byte array (32-byte) representation of 0.
	 */
	private static final byte[] ONE_BYTES = { (byte)0, (byte)0, (byte)0,  (byte)1 };


	/**
	 * The four byte array (32-bit) representation of 1.
	 */
	private static final byte[] ZERO_BYTES = { (byte)0, (byte)0, (byte)0,  (byte)0 };


	/**
	 * The byte array representation of the string "Encryption".
	 */
	private static final byte[] ENCRYPTION_BYTES = { 
	
		(byte)69, (byte)110, (byte)99, (byte)114, (byte)121, (byte)112, (byte)116, (byte)105, (byte)111, (byte)110
	};


	/**
	 * The byte array representation of the string "Integrity".
	 */
	private static final byte[] INTEGRITY_BYTES = {

		(byte)73, (byte)110, (byte)116, (byte)101, (byte)103, (byte)114, (byte)105, (byte)116, (byte)121
	};


	/**
	 * Generates a Content Encryption Key (CEK) from the specified 
	 * Content Master Key (CMK) and JOSE encryption method.
	 *
	 * @param key The Content Master Key (CMK). Must not be {@code null}.
	 * @param enc The JOSE encryption method. Must not be {@code null}.
	 * @param epu The value of the encryption PartyUInfo header parameter,
	 *            {@code null} if not specified.
	 * @param epv The value of the encryption PartyVInfo header parameter,
	 *            {@code null} if not specified.
	 *
	 * @return The generated AES CEK.
	 *
	 * @throws JOSEException If CEK generation failed.
	 */
	public static SecretKey generateCEK(final SecretKey key, 
		                            final EncryptionMethod enc,
		                            final byte[] epu,
		                            final byte[] epv)
		throws JOSEException {

		ByteArrayOutputStream baos = new ByteArrayOutputStream();

		int hashBitLength;

		try {
			// Write [0, 0, 0, 1]
			baos.write(ONE_BYTES);

			// Append CMK
			byte[] cmkBytes = key.getEncoded();
			baos.write(cmkBytes);

			// Append [CEK-bit-length...]
			final int cmkBitLength = cmkBytes.length * 8;
			hashBitLength = cmkBitLength;
			final int cekBitLength = cmkBitLength / 2;
			byte[] cekBitLengthBytes = intToFourBytes(cekBitLength);
			baos.write(cekBitLengthBytes);

			// Append the encryption method value, e.g. "A128CBC+HS256"
			byte[] encBytes = enc.toString().getBytes();
			baos.write(encBytes);

			// Append encryption PartyUInfo=Datalen || Data
			if (epu != null) {

				baos.write(intToFourBytes(epu.length));
				baos.write(epu);

			} else {
				baos.write(ZERO_BYTES);
			}

			// Append encryption PartyVInfo=Datalen || Data
			if (epv != null) {

				baos.write(intToFourBytes(epv.length));
				baos.write(epv);

			} else {
				baos.write(ZERO_BYTES);
			}

			// Append "Encryption" label
			baos.write(ENCRYPTION_BYTES);

		} catch (IOException e) {

			throw new JOSEException(e.getMessage(), e);
		}

		// Write out
		byte[] hashInput = baos.toByteArray();

		MessageDigest md;

		try {
			// SHA-256 or SHA-512
			md = MessageDigest.getInstance("SHA-" + hashBitLength);

		} catch (NoSuchAlgorithmException e) {

			throw new JOSEException(e.getMessage(), e);
		}

		byte[] hashOutput = md.digest(hashInput);

		byte[] cekBytes = new byte[hashOutput.length / 2];
		System.arraycopy(hashOutput, 0, cekBytes, 0, cekBytes.length);

		return new SecretKeySpec(cekBytes, "AES");
	}


	/**
	 * Generates a Content Integrity Key (CIK) from the specified 
	 * Content Master Key (CMK) and JOSE encryption method.
	 *
	 * @param key The Content Master Key (CMK). Must not be {@code null}.
	 * @param enc The JOSE encryption method. Must not be {@code null}.
	 * @param epu The value of the encryption PartyUInfo header parameter,
	 *            {@code null} if not specified.
	 * @param epv The value of the encryption PartyVInfo header parameter,
	 *            {@code null} if not specified.
	 *
	 * @return The generated HMAC SHA CIK.
	 *
	 * @throws JOSEException If CIK generation failed.
	 */
	public static SecretKey generateCIK(final SecretKey key, 
		                            final EncryptionMethod enc,
		                            final byte[] epu,
		                            final byte[] epv)
		throws JOSEException {

		ByteArrayOutputStream baos = new ByteArrayOutputStream();

		int hashBitLength;
		int cikBitLength;

		try {
			// Write [0, 0, 0, 1]
			baos.write(ONE_BYTES);

			// Append CMK
			byte[] cmkBytes = key.getEncoded();
			baos.write(cmkBytes);

			// Append [CIK-bit-length...]
			final int cmkBitLength = cmkBytes.length * 8;
			hashBitLength = cmkBitLength;
			cikBitLength = cmkBitLength;
			byte[] cikBitLengthBytes = intToFourBytes(cikBitLength);
			baos.write(cikBitLengthBytes);

			// Append the encryption method value, e.g. "A128CBC+HS256"
			byte[] encBytes = enc.toString().getBytes();
			baos.write(encBytes);

			// Append encryption PartyUInfo=Datalen || Data
			if (epu != null) {

				baos.write(intToFourBytes(epu.length));
				baos.write(epu);

			} else {
				baos.write(ZERO_BYTES);
			}

			// Append encryption PartyVInfo=Datalen || Data
			if (epv != null) {

				baos.write(intToFourBytes(epv.length));
				baos.write(epv);

			} else {
				baos.write(ZERO_BYTES);	
			}

			// Append "Encryption" label
			baos.write(INTEGRITY_BYTES);

		} catch (IOException e) {

			throw new JOSEException(e.getMessage(), e);
		}

		// Write out
		byte[] hashInput = baos.toByteArray();

		MessageDigest md;

		try {
			// SHA-256 or SHA-512
			md = MessageDigest.getInstance("SHA-" + hashBitLength);

		} catch (NoSuchAlgorithmException e) {

			throw new JOSEException(e.getMessage(), e);
		}

		byte[] hashOutput = md.digest(hashInput);

		byte[] cikBytes = hashOutput;

		// HMACSHA256 or HMACSHA512
		return new SecretKeySpec(cikBytes, "HMACSHA" + cikBitLength);
	}


	/**
	 * Returns a four byte array (32-bit) representation of the specified
	 * integer.
	 *
	 * @param i The integer.
	 *
	 * @return The four byte array representation.
	 */
	private static byte[] intToFourBytes(final int i) {
		
		byte[] res = new byte[4];
		res[0] = (byte) (i >>> 24);
		res[1] = (byte) ((i >>> 16) & 0xFF);
		res[2] = (byte) ((i >>> 8) & 0xFF);
		res[3] = (byte) (i & 0xFF);
		return res;
	}
}

