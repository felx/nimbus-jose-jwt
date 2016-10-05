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


import com.nimbusds.jose.util.Resource;
import junit.framework.TestCase;


public class ResourceTest extends TestCase {


	public void testWithContentType() {

		Resource resource = new Resource("content", "text/plain");
		assertEquals("content", resource.getContent());
		assertEquals("text/plain", resource.getContentType());
	}


	public void testUnspecifiedContentType() {

		Resource resource = new Resource("content", null);
		assertEquals("content", resource.getContent());
		assertNull(resource.getContentType());
	}


	public void testEmptyContent() {

		assertEquals("", new Resource("", null).getContent());
	}


	public void testRejectNullContent() {

		try {
			new Resource(null, null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The resource content must not be null", e.getMessage());
		}
	}
}
