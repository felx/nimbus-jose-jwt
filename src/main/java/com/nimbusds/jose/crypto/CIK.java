package com.nimbusds.jose.crypto;


import java.io.ByteArrayOutputStream;
import java.io.IOException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

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


	public static SecretKey generate(final byte[] keyBytes, final int cikBitLength, final Digest kdfDigest, final String encStr) 
		throws JOSEException {

		try {
			// "Integrity"
			final byte[] integrity = { 73, 110, 116, 101, 103, 114, 105, 116, 121 };

			int outputLengthInBits = cikBitLength;
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
			byte[] key = new byte[cikBitLength / 8];
			kdfConcatGenerator.generateBytes(key, 0, key.length);
		
			return new SecretKeySpec(key, "HMACSHA" + cikBitLength);

		} catch (IOException e) {
			
			throw new JOSEException(e.getMessage(), e);
		}
	}
}
