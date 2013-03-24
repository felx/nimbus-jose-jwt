package com.nimbusds.jose.crypto;


import java.io.ByteArrayOutputStream;
import java.io.IOException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.KDFParameters;

import com.nimbusds.jose.JOSEException;


/**
 * Static methods for JOSE Content Encryption Key (CEK) generation. Uses the 
 * BouncyCastle.org provider.
 *
 * @author Axel Nennker
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-03-24)
 */
class CEK {


	public static SecretKey generate(byte[] keyBytes, int cekBitLength, Digest kdfDigest, String encStr)
	 	throws JOSEException {

	 	try {
	 		final byte[] encryption = { 69, 110, 99, 114, 121, 112, 116, 105, 111, 110 };
			int outputLengthInBits = cekBitLength;
			byte[] encStrBytes = encStr.getBytes();

			ByteArrayOutputStream baos = new ByteArrayOutputStream(4 + encStrBytes.length + encryption.length);
			baos.write((byte) (outputLengthInBits >> 24));
			baos.write((byte) (outputLengthInBits >> 16));
			baos.write((byte) (outputLengthInBits >> 8));
			baos.write((byte) outputLengthInBits);
			baos.write(encStrBytes);
			baos.write(encryption);
			byte[] otherInfo = baos.toByteArray();

			ConcatKDF kdfConcatGenerator = new ConcatKDF(kdfDigest, otherInfo);
			kdfConcatGenerator.init(new KDFParameters(keyBytes, null));
			byte[] key = new byte[cekBitLength / 8];
			kdfConcatGenerator.generateBytes(key, 0, key.length);

			return new SecretKeySpec(key, "AES");

	 	} catch (IOException e) {

	 		throw new JOSEException(e.getMessage(), e);
	 	}
	}
}
