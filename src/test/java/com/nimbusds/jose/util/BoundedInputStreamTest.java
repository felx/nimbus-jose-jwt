/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2016, Connect2id Ltd and contributors.
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


import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import junit.framework.TestCase;


public class BoundedInputStreamTest extends TestCase {
	

	public void testBounded()
		throws Exception {
		
		String s = "";
		
		for (int i=0; i<100; i++) {
			s += "a";
		}
		
		assertEquals(100, s.length());
		
		InputStream stream = new ByteArrayInputStream(s.getBytes(StandardCharsets.UTF_8));
		
		BoundedInputStream bis = new BoundedInputStream(stream, 50);
		
		byte[] data = new byte[100];
		
		int readBytes = bis.read(data);
		
		assertEquals(50, readBytes);
		
		bis.close();
	}
}
