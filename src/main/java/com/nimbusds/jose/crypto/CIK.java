package com.nimbusds.jose.crypto;


import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.KDFParameters;

import com.nimbusds.jose.JOSEException;


/**
 * Static methods for Content Integrity Key (CIK) generation. Uses the 
 * BouncyCastle.org provider.
 *
 * @author Axel Nennker
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-03-24)
 */
class CIK {


	public static byte[] generateCIK(byte[] keyBytes, int cikByteLength, Digest kdfDigest, String encStr) 
		throws JOSEException {

		try {
			// "Integrity"
			final byte[] integrity = { 73, 110, 116, 101, 103, 114, 105, 116, 121 };

			int outputLengthInBits = cikByteLength * 8;
			byte[] encStrBytes = encStr.getBytes();

			ByteArrayOutputStream baos = new ByteArrayOutputStream(4 + encStrBytes.length + integrity.length);
			baos.write((byte) (outputLengthInBits >> 24));
			baos.write((byte) (outputLengthInBits >> 16));
			baos.write((byte) (outputLengthInBits >> 8));
			baos.write((byte) outputLengthInBits);
			baos.write(encStrBytes);
			baos.write(integrity);
			byte[] otherInfo = baos.toByteArray();

			ConcatKDF kdfConcatGenerator = new ConcatKDF(kdfDigest, otherInfo);
			kdfConcatGenerator.init(new KDFParameters(keyBytes, null));
			byte[] key = new byte[cikByteLength];
			kdfConcatGenerator.generateBytes(key, 0, key.length);
			return key;

		} catch (IOException e) {
			
			throw new JOSEException(e.getMessage(), e);
		}
	}
}
