package com.nimbusds.jose;


import com.nimbusds.util.Base64URL;


/**
 * Plain JOSE object.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-09-20)
 */
public class PlainObject extends JOSEObject {

	
	/**
	 * The header.
	 */
	private PlainHeader header;
	
	
	/**
	 * Creates a new plain JOSE object with a default {@link PlainHeader} 
	 * and the specified payload.
	 *
	 * @param payload The payload. Must not be {@code null}.
	 */
	public PlainObject(final Payload payload) {
		
		if (payload == null)
			throw new IllegalArgumentException("The payload must not be null");
			
		setPayload(payload);
		
		header = new PlainHeader();
	}
	
	
	/**
	 * Creates a new plain JOSE object with the specified header and 
	 * payload.
	 *
	 * @param header  The plain header. Must not be {@code null}.
	 * @param payload The payload. Must not be {@code null}.
	 */
	public PlainObject(final PlainHeader header, final Payload payload) {
			
		if (header == null)
			throw new IllegalArgumentException("The plain header must not be null");
			
		this.header = header;
		
		if (payload == null)
			throw new IllegalArgumentException("The payload must not be null");
		
		setPayload(payload);
	}
	
	
	/**
	 * Creates a new plain JOSE object with the specified Base64URL-encoded 
	 * parts.
	 *
	 * @param firstPart  The first part, corresponding to the plain header. 
	 *                   Must not be {@code null}.
	 * @param secondPart The second part, corresponding to the payload. Must 
	 *                   not be {@code null}.
	 *
	 * @throws ParseException If parsing of the serialised parts failed.
	 */
	public PlainObject(final Base64URL firstPart, final Base64URL secondPart)
		throws ParseException {
	
		if (firstPart == null)
			throw new IllegalArgumentException("The first part must not be null");
		
		try {
			header = PlainHeader.parse(firstPart);
			
		} catch (ParseException e) {
		
			throw new ParseException("Invalid plain header: " + e.getMessage(), e);
		}
		
		if (secondPart == null)
			throw new IllegalArgumentException("The second part must not be null");
	
		setPayload(new Payload(secondPart));
	}
	
	
	/**
	 * Gets the header of this plain JOSE object.
	 *
	 * @return The header.
	 */
	public ReadOnlyPlainHeader getHeader() {
	
		return header;
	}
	
	
	/**
	 * Serialises this plain JOSE object to its compact format consisting of 
	 * Base64URL-encoded parts delimited by period ('.') characters.
	 *
	 * <pre>
	 * [header-base64url].[payload-base64url].[]
	 * </pre>
	 *
	 * @return The serialised plain JOSE object.
	 */
	@Override
	public String serialize() {
	
		StringBuilder sb = new StringBuilder(header.toBase64URL().toString());
		sb.append('.');
		sb.append(getPayload().toBase64URL().toString());
		sb.append('.');
		return sb.toString();
	}
	
	
	/**
	 * Parses a plain JOSE object from the specified string in compact 
	 * format.
	 *
	 * @param s The string to parse. Must not be {@code null}.
	 *
	 * @return The plain JOSE object.
	 *
	 * @throws ParseException If the string couldn't be parsed to a valid 
	 *                        plain JOSE object.
	 */
	public static PlainObject parse(final String s)
		throws ParseException {
	
		Base64URL[] parts = JOSEObject.split(s);
		
		if (! parts[2].toString().isEmpty())
			throw new ParseException("Unexpected third part in the plain JOSE object");
		
		return new PlainObject(parts[0], parts[1]);
	}
}
