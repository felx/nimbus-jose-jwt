package com.nimbusds.jose.util;


import junit.framework.TestCase;
import org.junit.Ignore;
import org.junit.Test;
import static org.junit.Assert.assertEquals;

/**
 * Tests DEFLATE compression.
 *
 * @version $version$ (2012-09-29)
 */
public class DeflateUtilsTest  {
	
	@Ignore("Test fails, may due to https://bitbucket.org/nimbusds/nimbus-jose-jwt/issue/2/compressionutils-deflate-bug")
	@Test
	public void testRun()
		throws Exception {
	
		final String text = "Hello world!";
		final byte[] textBytes = text.getBytes("UTF-8");
			
		byte[] compressed = DeflateUtils.compress(textBytes);
		
		byte[] textBytesDecompressed = DeflateUtils.decompress(compressed);
		String textDecompressed = new String(textBytesDecompressed, "UTF-8");
		
		assertEquals("byte length check", textBytes.length, textBytesDecompressed.length);
		
		assertEquals("text length check", text.length(), textDecompressed.length());
		
		assertEquals("text comparison", text, textDecompressed);
	}
}
