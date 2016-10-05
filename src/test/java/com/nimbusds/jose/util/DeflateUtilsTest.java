/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2016, Connect2id Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.nimbusds.jose.util;


import com.nimbusds.jose.util.DeflateUtils;
import junit.framework.TestCase;


/**
 * Tests DEFLATE compression.
 *
 * @version 2013-03-26
 */
public class DeflateUtilsTest extends TestCase  {


	public void testDeflateAndInflate()
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
