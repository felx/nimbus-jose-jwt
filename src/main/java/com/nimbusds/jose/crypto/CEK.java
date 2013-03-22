package com.nimbusds.jose.crypto;


import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.KDFParameters;

import com.nimbusds.jose.JOSEException;


/**
 * Static methods for Content Encryption Key (CEK) generation. Uses the 
 * BouncyCastle.org provider.
 *
 * @author Axel Nennker
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-03-22)
 */
class CEK {


	public static byte[] generateCEK(byte[] keyBytes, int cekByteLength, Digest kdfDigest, String encStr)
	 	throws JOSEException {

	 	try {
	 		final byte[] encryption = { 69, 110, 99, 114, 121, 112, 116, 105, 111, 110 };
			int outputLengthInBits = cekByteLength * 8;
			byte[] encStrBytes = encStr.getBytes();

			ByteArrayOutputStream baos = new ByteArrayOutputStream(4 + encStrBytes.length + encryption.length);
			baos.write((byte) (outputLengthInBits >> 24));
			baos.write((byte) (outputLengthInBits >> 16));
			baos.write((byte) (outputLengthInBits >> 8));
			baos.write((byte) outputLengthInBits);
			baos.write(encStrBytes);
			baos.write(encryption);
			byte[] otherInfo = baos.toByteArray();

			KDFConcatGenerator kdfConcatGenerator = new KDFConcatGenerator(kdfDigest, otherInfo);
			kdfConcatGenerator.init(new KDFParameters(keyBytes, null));
			byte[] key = new byte[cekByteLength];
			kdfConcatGenerator.generateBytes(key, 0, key.length);
			return key;

	 	} catch (IOException e) {

	 		throw new JOSEException(e.getMessage(), e);
	 	}
	}
}
