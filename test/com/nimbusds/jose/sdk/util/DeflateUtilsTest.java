package com.nimbusds.jose.sdk.util;


import junit.framework.TestCase;


/**
 * Tests DEFLATE compression.
 *
 * @version $version$ (2012-09-25)
 */
public class DeflateUtilsTest extends TestCase {
	
	
	public void testRun()
		throws Exception {
	
		final String text = "abc123";
		final byte[] textBytes = text.getBytes("UTF-8");
			
		byte[] compressed = DeflateUtils.compress(textBytes);
		
		byte[] textBytesDecompressed = DeflateUtils.decompress(compressed);
		String textDecompressed = new String(textBytesDecompressed, "UTF-8");
		
		assertEquals(text.length(), textDecompressed.length());
		assertEquals(text, textDecompressed);
	}
}
