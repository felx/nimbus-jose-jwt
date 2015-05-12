package com.nimbusds.jose.crypto;


import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jca.JCAProviderAware;
import com.nimbusds.jose.util.ByteUtils;
import com.nimbusds.jose.util.IntegerUtils;


/**
 * Concatenation Key Derivation Function (KDF). Provides static
 * methods to generate Content Encryption Keys (CEKs) and Content Integrity 
 * Keys (CIKs) from a Content Master Key (CMKs), as used in 
 * {@code A128CBC+HS256} and {@code A256CBC+HS512} encryption (deprecated).
 *
 * <p>See draft-ietf-jose-json-web-encryption-08, appendices A.4 and A.5.
 *
 * <p>See NIST.800-56A.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-05-12)
 */
class ConcatKDF implements JCAProviderAware {


	/**
	 * The JCA name of the hash algorithm.
	 */
	private final String jcaHashAlg;


	/**
	 * The JCA provider, {@code null} implies the default one.
	 */
	private Provider jcaProvider;


	/**
	 * Creates a new concatenation Key Derivation Function (KDF) with the
	 * specified hash algorithm.
	 *
	 * @param jcaHashAlg The JCA name of the hash algorithm. Must be
	 *                   supported and not {@code null}.
	 */
	public ConcatKDF(final String jcaHashAlg) {

		if (jcaHashAlg == null) {
			throw new IllegalArgumentException("The JCA hash algorithm must not be null");
		}

		this.jcaHashAlg = jcaHashAlg;
	}


	/**
	 * Returns the JCA name of the hash algorithm.
	 *
	 * @return The JCA name of the hash algorithm.
	 */
	public String getHashAlgorithm() {

		return jcaHashAlg;
	}


	@Override
	public void setJCAProvider(Provider jcaProvider) {

		this.jcaProvider = jcaProvider;
	}


	@Override
	public Provider getJCAProvider() {

		return jcaProvider;
	}


	public SecretKey deriveKey(final SecretKey sharedSecret,
				   final int keyLength,
				   final byte[] otherInfo)
		throws JOSEException {

		ByteArrayOutputStream baos = new ByteArrayOutputStream();

		final MessageDigest md = getMessageDigest();

		for (int i=1; i <= computeDigestCycles(md.getDigestLength(), keyLength); i++) {

			byte[] counterBytes = IntegerUtils.toBytes(i);

			md.update(counterBytes);
			md.update(sharedSecret.getEncoded());
			md.update(otherInfo);

			try {
				baos.write(md.digest());
			} catch (IOException e) {
				throw new JOSEException("Couldn't write derived key: " + e.getMessage(), e);
			}
		}

		byte[] derivedKeyMaterial = baos.toByteArray();

		final int keyLengthBytes = ByteUtils.byteLength(keyLength);

		if (derivedKeyMaterial.length == keyLengthBytes) {
			// Return immediately
			return new SecretKeySpec(derivedKeyMaterial, "AES");
		}

		return new SecretKeySpec(ByteUtils.subArray(derivedKeyMaterial, 0, keyLengthBytes), "AES");
	}


	public SecretKey deriveKey(final SecretKey sharedSecret,
				   final int keyLength,
				   final byte[] algID,
				   final byte[] partyUInfo,
				   final byte[] partyVInfo,
				   final byte[] suppPubInfo,
				   final byte[] suppPrivInfo)
		throws JOSEException {

		final byte[] otherInfo = composeOtherInfo(algID, partyUInfo, partyVInfo, suppPubInfo, suppPrivInfo);

		return deriveKey(sharedSecret, keyLength, otherInfo);
	}


	/**
	 * Composes the other info as {@code algID || partyUInfo || partyVInfo
	 * || suppPubInfo || suppPrivInfo}.
	 *
	 * @param algID        The algorithm identifier, {@code null} if not
	 *                     specified.
	 * @param partyUInfo   The partyUInfo, {@code null} if not specified.
	 * @param partyVInfo   The partyVInfo {@code null} if not specified.
	 * @param suppPubInfo  The suppPubInfo, {@code null} if not specified.
	 * @param suppPrivInfo The suppPrivInfo, {@code null} if not specified.
	 *
	 * @return The resulting other info.
	 */
	public static byte[] composeOtherInfo(final byte[] algID,
					      final byte[] partyUInfo,
					      final byte[] partyVInfo,
					      final byte[] suppPubInfo,
					      final byte[] suppPrivInfo) {

		return ByteUtils.concat(algID, partyUInfo, partyVInfo, suppPubInfo, suppPrivInfo);
	}


	/**
	 * Returns a message digest instance for the configured
	 * {@link #jcaHashAlg hash algorithm}.
	 *
	 * @return The message digest instance.
	 *
	 * @throws JOSEException If the message digest algorithm is not
	 *                       supported by the underlying JCA provider.
	 */
	private MessageDigest getMessageDigest()
		throws JOSEException {

		final Provider provider = getJCAProvider();

		try {
			if (provider == null)
				return MessageDigest.getInstance(jcaHashAlg);
			else
				return MessageDigest.getInstance(jcaHashAlg, provider);
		} catch (NoSuchAlgorithmException e) {
			throw new JOSEException("Couldn't get message digest for KDF: " + e.getMessage(), e);
		}
	}


	/**
	 * Computes the required digest (hashing) cycles for the specified
	 * message digest length and derived key length.
	 *
	 * @param digestLength The length of the message digest.
	 * @param keyLength    The length of the derived key.
	 *
	 * @return The digest cycles.
	 */
	public static int computeDigestCycles(final int digestLength, final int keyLength) {

		double digestCycles = (double) keyLength / (double) digestLength;
		return (int) Math.ceil(digestCycles);
	}


	/**
	 * Encodes no / empty data as an empty byte array.
	 *
	 * @return The encoded data.
	 */
	public static byte[] encodeNoData() {

		return new byte[0];
	}


	/**
	 * Encodes the specified integer data as a four byte array.
	 *
	 * @param data The integer data to encode.
	 *
	 * @return The encoded data.
	 */
	public static byte[] encodeIntData(final int data) {

		return IntegerUtils.toBytes(data);
	}


	/**
	 * Encodes the specified string data as {@code data.length || data}.
	 *
	 * @param data The string data, UTF-8 encoded. May be {@code null}.
	 *
	 * @return The encoded data.
	 */
	public static byte[] encodeStringData(final String data) {

		byte[] bytes = data != null ? data.getBytes(Charset.forName("UTF-8")) : null;
		return encodeDataWithLength(bytes);
	}


	/**
	 * Encodes the specified data as {@code data.length || data}.
	 *
	 * @param data The data to encode, may be {@code null}.
	 *
	 * @return The encoded data.
	 */
	public static byte[] encodeDataWithLength(final byte[] data) {

		byte[] bytes = data != null ? data : new byte[0];
		byte[] length = IntegerUtils.toBytes(bytes.length);
		return ByteUtils.concat(length, bytes);
	}


	/**
	 * The four byte array (32-byte) representation of 1.
	 */
	private static final byte[] ONE_BYTES = { (byte)0, (byte)0, (byte)0,  (byte)1 };


	/**
	 * The four byte array (32-bit) representation of 0.
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
			byte[] cekBitLengthBytes = IntegerUtils.toBytes(cekBitLength);
			baos.write(cekBitLengthBytes);

			// Append the encryption method value, e.g. "A128CBC+HS256"
			byte[] encBytes = enc.toString().getBytes();
			baos.write(encBytes);

			// Append encryption PartyUInfo=Datalen || Data
			if (epu != null) {

				baos.write(IntegerUtils.toBytes(epu.length));
				baos.write(epu);

			} else {
				baos.write(ZERO_BYTES);
			}

			// Append encryption PartyVInfo=Datalen || Data
			if (epv != null) {

				baos.write(IntegerUtils.toBytes(epv.length));
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
			byte[] cikBitLengthBytes = IntegerUtils.toBytes(cikBitLength);
			baos.write(cikBitLengthBytes);

			// Append the encryption method value, e.g. "A128CBC+HS256"
			byte[] encBytes = enc.toString().getBytes();
			baos.write(encBytes);

			// Append encryption PartyUInfo=Datalen || Data
			if (epu != null) {

				baos.write(IntegerUtils.toBytes(epu.length));
				baos.write(epu);

			} else {
				baos.write(ZERO_BYTES);
			}

			// Append encryption PartyVInfo=Datalen || Data
			if (epv != null) {

				baos.write(IntegerUtils.toBytes(epv.length));
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

		// HMACSHA256 or HMACSHA512
		return new SecretKeySpec(md.digest(hashInput), "HMACSHA" + cikBitLength);
	}
}

