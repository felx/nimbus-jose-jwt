package com.nimbusds.jose.util.url;


import net.jcip.annotations.Immutable;


/**
 * Resource with optional associated content type.
 */
@Immutable
public class Resource {


	/**
	 * The content.
	 */
	private final String content;


	/**
	 * The content type.
	 */
	private final String contentType;


	/**
	 * Creates a new resource with optional associated content type.
	 *
	 * @param content     The resource content, empty string if none. Must 
	 *                    not be {@code null}.
	 * @param contentType The resource content type, {@code null} if not
	 *                    specified.
	 */
	public Resource(final String content, final String contentType) {

		if (content == null) {
			throw new IllegalArgumentException("The resource content must not be null");
		}

		this.content = content;
		this.contentType = contentType;
	}


	/**
	 * Gets the content of this resource.
	 *
	 * @return The content, empty string if none.
	 */
	public String getContent() {

		return content;
	}


	/**
	 * Gets the content type of this resource.
	 *
	 * @return The content type, {@code null} if not specified.
	 */
	public String getContentType() {

		return contentType;
	}
}
