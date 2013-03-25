package com.nimbusds.jose.crypto;


import java.io.ByteArrayOutputStream;
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
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-03-25)
 */
class ConcatKDF {


	/**
	 * The four byte array (32-byte) representation of 0.
	 */
	private static final byte[] ONE_BYTES = { (byte)0, (byte)0, (byte)0,  (byte)0};


	/**
	 * The four byte array (32-bit) representation of 1.
	 */
	private static final byte[] ZERO_BYTES = { (byte)0, (byte)0, (byte)0,  (byte)1};


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


	public static SecretKey generateCEK(final SecretKey key, final EncryptionMethod enc)
		throws JOSEException {

		ByteArrayOutputStream baos = new ByteArrayOutputStream();

		// Write [0, 0, 0, 1]
		baos.write(ONE_BYTES, 0, ONE_BYTES.length);

		// Append CMK
		byte[] cmkBytes = key.getEncoded();
		baos.write(cmkBytes, 0, cmkBytes.length);

		// Append [CEK-bit-length...]
		final int cmkBitLength = cmkBytes.length * 8;
		final int cekBitLength = cmkBitLength / 2;
		byte[] cekBitLengthBytes = intToFourBytes(cekBitLength);
		baos.write(cekBitLengthBytes, 0, cekBitLengthBytes.length);

		// Append the encryption method value, e.g. "A128CBC+HS256"
		byte[] encBytes = enc.toString().getBytes();
		baos.write(encBytes, 0, encBytes.length);

		// Append encryption PartyUInfo [0, 0, 0, 0]
		baos.write(ZERO_BYTES, 0, ZERO_BYTES.length);

		// Append encryption PartyVInfo [0, 0, 0, 0]
		baos.write(ZERO_BYTES, 0, ZERO_BYTES.length);

		// Append "Encryption" label
		baos.write(ENCRYPTION_BYTES, 0, ENCRYPTION_BYTES.length);

		// Write out
		byte[] hashInput = baos.toByteArray();

		MessageDigest md;

		try {
			md = MessageDigest.getInstance("SHA-" + cmkBitLength);

		} catch (NoSuchAlgorithmException e) {

			throw new JOSEException(e.getMessage(), e);
		}

		byte[] hashOutput = md.digest(hashInput);

		byte[] cekBytes = new byte[hashOutput.length / 2];
		System.arraycopy(hashOutput, 0, cekBytes, 0, cekBytes.length);

		return new SecretKeySpec(cekBytes, "AES");
	}


	public static SecretKey generateCIK(final SecretKey key, final EncryptionMethod enc)
		throws JOSEException {

		ByteArrayOutputStream baos = new ByteArrayOutputStream();

		// Write [0, 0, 0, 1]
		baos.write(ONE_BYTES, 0, ONE_BYTES.length);

		// Append CMK
		byte[] cmkBytes = key.getEncoded();
		baos.write(cmkBytes, 0, cmkBytes.length);

		// Append [CIK-bit-length...]
		final int cmkBitLength = cmkBytes.length * 8;	
		final int cikBitLength = cmkBitLength;
		byte[] cikBitLengthBytes = intToFourBytes(cikBitLength);
		baos.write(cikBitLengthBytes, 0, cikBitLengthBytes.length);

		// Append the encryption method value, e.g. "A128CBC+HS256"
		byte[] encBytes = enc.toString().getBytes();
		baos.write(encBytes, 0, encBytes.length);

		// Append encryption PartyUInfo [0, 0, 0, 0]
		baos.write(ZERO_BYTES, 0, ZERO_BYTES.length);

		// Append encryption PartyVInfo [0, 0, 0, 0]
		baos.write(ZERO_BYTES, 0, ZERO_BYTES.length);

		// Append "Encryption" label
		baos.write(INTEGRITY_BYTES, 0, INTEGRITY_BYTES.length);

		// Write out
		byte[] hashInput = baos.toByteArray();

		MessageDigest md;

		try {
			md = MessageDigest.getInstance("SHA-" + cmkBitLength);

		} catch (NoSuchAlgorithmException e) {

			throw new JOSEException(e.getMessage(), e);
		}

		byte[] hashOutput = md.digest(hashInput);

		byte[] cikBytes = hashOutput;

		return new SecretKeySpec(cikBytes, "HMACSHA" + cikBitLength);
	}


	private static byte[] intToFourBytes(final int i) {
		
		byte[] res = new byte[4];
		res[0] = (byte) (i >>> 24);
		res[1] = (byte) ((i >>> 16) & 0xFF);
		res[2] = (byte) ((i >>> 8) & 0xFF);
		res[3] = (byte) (i & 0xFF);
		return res;
	}
}

