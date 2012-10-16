package com.nimbusds.jose;


import java.io.UnsupportedEncodingException;

import java.text.ParseException;

import java.util.Set;

import com.nimbusds.jose.util.Base64URL;


/**
 * JSON Web Signature (JWS) object.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-04)
 */
public class JWSObject extends JOSEObject {


	/**
	 * Enumeration of the states of a JSON Web Signature (JWS) object.
	 */
	public static enum State {
	
	
		/**
		 * The JWS object is created but not signed yet.
		 */
		UNSIGNED,
		
		
		/**
		 * The JWS object is signed but not validated yet.
		 */
		SIGNED,
		
		
		/**
		 * The JWS object is signed and was successfully validated.
		 */
		VALIDATED;
	}
	
	
	/**
	 * The header.
	 */
	private JWSHeader header;
	
	
	/**
	 * The signable content of this JWS object.
	 *
	 * <p>Format:
	 *
	 * <pre>
	 * [header-base64url].[payload-base64url]
	 * </pre>
	 */
	private byte[] signableContent;
	
	
	/**
	 * The signature, {@code null} if unsigned.
	 */
	private Base64URL signature;
	
	
	/**
	 * The JWS object state.
	 */
	private State state;
	
	
	/**
	 * Creates a new to-be-signed JSON Web Signature (JWS) object with the 
	 * specified header and payload. The initial state will be 
	 * {@link State#UNSIGNED unsigned}.
	 *
	 * @param header  The JWS header. Must not be {@code null}.
	 * @param payload The payload. Must not be {@code null}.
	 */
	public JWSObject(final JWSHeader header, final Payload payload) {
	
		if (header == null)
			throw new IllegalArgumentException("The JWS header must not be null");
			
		this.header = header;
		
		if (payload == null)
			throw new IllegalArgumentException("The payload must not be null");
		
		setPayload(payload);
		
		setSignableContent(header.toBase64URL(), payload.toBase64URL());
		
		signature = null;
		
		state = State.UNSIGNED;
	}
	
	
	/**
	 * Creates a new signed JSON Web Signature (JWS) object with the 
	 * specified serialised parts. The state will be 
	 * {@link State#SIGNED signed}.
	 *
	 * @param firstPart  The first part, corresponding to the JWS header. 
	 *                   Must not be {@code null}.
	 * @param secondPart The second part, corresponding to the payload. Must
	 *                   not be {@code null}.
	 * @param thirdPart  The third part, corresponding to the signature.
	 *                   Must not be {@code null}.
	 *
	 * @throws ParseException If parsing of the serialised parts failed.
	 */
	public JWSObject(final Base64URL firstPart, final Base64URL secondPart, final Base64URL thirdPart)	
		throws ParseException {
	
		if (firstPart == null)
			throw new IllegalArgumentException("The first part must not be null");
		
		try {
			this.header = JWSHeader.parse(firstPart);
			
		} catch (ParseException e) {
		
			throw new ParseException("Invalid JWS header: " + e.getMessage(), 0);
		}
		
		if (secondPart == null)
			throw new IllegalArgumentException("The second part must not be null");
	
		setPayload(new Payload(secondPart));
		
		setSignableContent(firstPart, secondPart);
	
		if (thirdPart == null)
			throw new IllegalArgumentException("The third part must not be null");
		
		signature = thirdPart;
		
		state = State.SIGNED; // but not validated yet!
	}
	
	
	@Override
	public ReadOnlyJWSHeader getHeader() {
	
		return header;
	}
	
	
	/**
	 * Sets the signable content of this JWS object.
	 *
	 * <p>Format:
	 *
	 * <pre>
	 * [header-base64url].[payload-base64url]
	 * </pre>
	 *
	 * @param firstPart  The first part, corresponding to the JWS header.
	 *                   Must not be {@code null}.
	 * @param secondPart The second part, corresponding to the payload. Must
	 *                   not be {@code null}.
	 */
	private void setSignableContent(final Base64URL firstPart, final Base64URL secondPart) {
	
		StringBuilder sb = new StringBuilder(firstPart.toString());
		sb.append('.');
		sb.append(secondPart.toString());

		try {
			signableContent = sb.toString().getBytes("UTF-8");
			
		} catch (UnsupportedEncodingException e) {
		
			// UTF-8 should always be supported
		}
	}
	
	
	/**
	 * Gets the signable content of this JWS object.
	 *
	 * <p>Format:
	 *
	 * <pre>
	 * [header-base64url].[payload-base64url]
	 * </pre>
	 *
	 * @return The signable content, ready for passing to the signing or
	 *         validation service.
	 */
	public byte[] getSignableContent() {
	
		return signableContent;
	}
	
	
	/**
	 * Gets the signature of this JWS object.
	 *
	 * @return The signature, {@code null} if the JWS object is not signed 
	 *         yet.
	 */
	public Base64URL getSignature() {
	
		return signature;
	}
	
	
	/**
	 * Gets the state of this JWS object.
	 *
	 * @return The state.
	 */
	public State getState() {
	
		return state;
	}
	
	
	/**
	 * Ensures the current state is {@link State#UNSIGNED unsigned}.
	 *
	 * @throws IllegalStateException If the current state is not unsigned.
	 */
	private void ensureUnsignedState() {
	
		if (state != State.UNSIGNED)
			throw new IllegalStateException("The JWS object must be in an unsigned state");
	}
	
	
	/**
	 * Ensures the current state is {@link State#SIGNED signed} or
	 * {@link State#VALIDATED validated}.
	 *
	 * @throws IllegalStateException If the current state is not signed or
	 *                               validated.
	 */
	private void ensureSignedOrValidatedState() {
	
		if (state != State.SIGNED && state != State.VALIDATED)
			throw new IllegalStateException("The JWS object must be in a signed or validated state");
	}
	
	
	/**
	 * Ensures the specified JWS signer supports the algorithm of this JWS
	 * object.
	 *
	 * @throws JOSEException If the JWS algorithm is not supported.
	 */
	private void ensureJWSSignerSupport(final JWSSigner signer)
		throws JOSEException {
	
		if (! signer.supportedAlgorithms().contains(getHeader().getAlgorithm())) {
		
			throw new JOSEException("The \"" + getHeader().getAlgorithm() + 
			                        "\" algorithm is not supported by the JWS signer");
		}
	}
	
	
	/**
	 * Ensures the specified JWS validator accepts the algorithm and the 
	 * headers of this JWS object.
	 *
	 * @throws JOSEException If the JWS algorithm or headers are not 
	 *                       accepted.
	 */
	private void ensureJWSValidatorAcceptance(final JWSValidator validator)
		throws JOSEException {
		
		JWSHeaderFilter filter = validator.getJWSHeaderFilter();
		
		if (filter == null)
			return;
		
		if (! filter.getAcceptedAlgorithms().contains(getHeader().getAlgorithm())) {
		
			throw new JOSEException("The \"" + getHeader().getAlgorithm() + 
			                        "\" algorithm is not accepted by the JWS validator");
		}
			
		
		if (! filter.getAcceptedParameters().containsAll(getHeader().getIncludedParameters())) {
		
			throw new JOSEException("One or more header parameters not accepted by the JWS validator");
		}
	}
	
	
	/**
	 * Signs this JWS object with the specified signer. The JWS object must
	 * be in a {@link State#UNSIGNED unsigned} state.
	 *
	 * @param signer The JWS signer. Must not be {@code null}.
	 *
	 * @throws IllegalStateException If the JWS object is not in an 
	 *                               {@link State#UNSIGNED unsigned state}.
	 * @throws JOSEException         If the JWS object couldn't be signed.
	 */
	public void sign(final JWSSigner signer)
		throws JOSEException {
	
		ensureUnsignedState();
		
		ensureJWSSignerSupport(signer);
		
		signature = signer.sign(getHeader(), getSignableContent());
	
		state = State.SIGNED;
	}
		
	
	/**
	 * Checks the signature of this JWS object with the specified validator. 
	 * The JWS object must be in a {@link State#SIGNED signed} state.
	 *
	 * @param validator The JWS validator. Must not be {@code null}.
	 *
	 * @return {@code true} if the signature was successfully validated, 
         *         else {@code false} if the signature was found to be invalid.
	 *
	 * @throws IllegalStateException If the JWS object is not in a 
	 *                               {@link State#SIGNED signed} or
	 *                               {@link State#VALIDATED validated 
	 *                               state}.
	 * @throws JOSEException         If the JWS object couldn't be validated.
	 */
	public boolean validate(final JWSValidator validator)
		throws JOSEException {
		
		ensureSignedOrValidatedState();
		
		ensureJWSValidatorAcceptance(validator);
		
		boolean valid = validator.validate(getHeader(), getSignableContent(), getSignature());
		
		if (valid)
			state = State.VALIDATED;
			
		return valid;
	}
	
	
	/**
	 * Serialises this JWS object to its compact format consisting of 
	 * Base64URL-encoded parts delimited by period ('.') characters. It must 
	 * be in a {@link State#SIGNED signed} or 
	 * {@link State#VALIDATED validated} state.
	 *
	 * <pre>
	 * [header-base64url].[payload-base64url].[signature-base64url]
	 * </pre>
	 *
	 * @return The serialised JWS object.
	 *
	 * @throws IllegalStateException If the JWS object is not in a 
	 *                               {@link State#SIGNED signed} or
	 *                               {@link State#VALIDATED validated 
	 *                               state}.
	 */
	@Override
	public String serialize() {
	
		ensureSignedOrValidatedState();
		
		StringBuilder sb = new StringBuilder(header.toBase64URL().toString());
		sb.append('.');
		sb.append(getPayload().toBase64URL().toString());
		sb.append('.');
		sb.append(signature.toString());
		return sb.toString();
	}
	
	
	/**
	 * Parses a JWS object from the specified string in compact format. The
	 * parsed JWS object will be given a {@link State#SIGNED} state.
	 *
	 * @param s The string to parse. Must not be {@code null}.
	 *
	 * @return The JWS object.
	 *
	 * @throws ParseException If the string couldn't be parsed to a valid 
	 *                        JWS object.
	 */
	public static JWSObject parse(String s)
		throws ParseException {
	
		Base64URL[] parts = JOSEObject.split(s);
		
		if (parts.length != 3)
			throw new ParseException("Unexpected number of Base64URL parts, must be three", 0);
		
		return new JWSObject(parts[0], parts[1], parts[2]);
	}
}
