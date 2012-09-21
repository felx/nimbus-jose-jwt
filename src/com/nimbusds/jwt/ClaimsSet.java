package com.nimbusds.jwt;


import java.util.Collections;
import java.util.HashSet;
import java.util.Set;


/**
 * JSON Web Token (JWT) claims set.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-09-21)
 */
public class ClaimsSet {


	/**
	 * The reserved claim names.
	 */
	private static final Set<String> RESERVED_CLAIM_NAMES;
	
	
	/**
	 * Initialises the reserved claim name set.
	 */
	static {
		Set<String> n = new HashSet<String>();
		
		n.add("exp");
		n.add("nbf");
		n.add("iat");
		n.add("iss");
		n.add("aud");
		n.add("prn");
		n.add("jti");
		n.add("typ");
		
		RESERVED_CLAIM_NAMES = Collections.unmodifiableSet(n);
	}
	
	
	/**
	 * The expiration time claim.
	 */
	private long exp;
	
	
	/**
	 * The not-before claim.
	 */
	private long nbf;
	
	
	/**
	 * The issued-at claim.
	 */
	private long iat;
	
	
	/**
	 * The issuer claim.
	 */
	private String iss;
	
	
	/**
	 * The audience claim.
	 */
	private String aud;
	
	
	/**
	 * The principal claim.
	 */
	private String prn;
	
	
	/**
	 * The JWT ID claim.
	 */
	private String jti;
	
	
	/**
	 * The type claim.
	 */
	private String typ;
	
	
	/**
	 * Creates a new empty claims set.
	 */
	public ClaimsSet() {
	
		// Nothing to do
	}
	
	
	/**
	 * Gets the reserved claim names.
	 *
	 * @return The reserved claim names, as an unmodifiable set.
	 */
	public static Set<String> getReservedNames() {
	
		return RESERVED_CLAIM_NAMES;
	}
	
	
	/**
	 * Gets the expiration time ({@code exp}) claim.
	 *
	 * @return The expiration time, -1 if not specified.
	 */
	public long getExpirationTimeClaim() {
	
		return exp;
	}
	
	
	/**
	 * Sets the expiration time ({@code exp}) claim.
	 *
	 * @param exp The expiration time, -1 if not specified.
	 */
	public void setExpirationTimeClaim(final long exp) {
	
		this.exp = exp;
	}
	
	
	/**
	 * Gets the not-before ({@code nbf}) claim.
	 *
	 * @return The not-before claim, -1 if not specified.
	 */
	public long getNotBeforeClaim() {
	
		return nbf;
	}
	
	
	/**
	 * Sets the not-before ({@code nbf}) claim.
	 *
	 * @param nbf The not-before claim, -1 if not specified.
	 */
	public void setNotBeforeClaim(final long nbf) {
	
		this.nbf = nbf;
	}
	
	
	/**
	 * Gets the issued-at ({@code iat}) claim.
	 *
	 * @return The issued-at claim, -1 if not specified.
	 */
	public long getIssuedAtClaim() {
	
		return iat;
	}
	
	
	/**
	 * Sets the issued-at ({@code iat}) claim.
	 *
	 * @param iat The issued-at claim, -1 if not specified.
	 */
	public void setIssuedAtClaim(final long iat) {
	
		this.iat = iat;
	}
	
	
	/**
	 * Gets the issuer ({@code iss}) claim.
	 *
	 * @return The issuer claim, {@code null} if not specified.
	 */
	public String getIssuerClaim() {
	
		return iss;
	}
	
	
	/**
	 * Sets the issuer ({@code iss}) claim.
	 *
	 * @param iss The issuer claim, {@code null} if not specified.
	 */
	public void setIssuerClaim(final String iss) {
	
		this.iss = iss;
	}
	
	
	/**
	 * Gets the audience ({@code aud}) clam.
	 *
	 * @return The audience claim, {@code null} if not specified.
	 */
	public String getAudienceClaim() {
	
		return iss;
	}
	
	
	/**
	 * Sets the audience ({@code aud}) clam.
	 *
	 * @param aud The audience claim, {@code null} if not specified.
	 */
	public void setAudienceClaim(final String aud) {
	
		this.aud = aud;
	}
	
	
	/**
	 * Gets the principal ({@code prn}) claim.
	 *
	 * @return The principal claim, {@code null} if not specified.
	 */
	public String getPrincipalClaim() {
	
		return prn;
	}
	
	
	/**
	 * Sets the principal ({@code prn}) claim.
	 *
	 * @param prn The principal claim, {@code null} if not specified.
	 */
	public void setPrincipalClaim(final String prn) {
	
		this.prn = prn;
	}
	
	
	/**
	 * Gets the JWT ID ({@code jti}) claim.
	 *
	 * @return The JWT ID claim, {@code null} if not specified.
	 */
	public String getJWTIDClaim() {
	
		return jti;
	}
	
	
	/**
	 * Sets the JWT ID ({@code jti}) claim.
	 *
	 * @param jti The JWT ID claim, {@code null} if not specified.
	 */
	public void setJWTIDClaim(final String jti) {
	
		this.jti = jti;
	}
	
	
	/**
	 * Gets the type ({@code typ}) claim.
	 *
	 * @return The type claim, {@code null} if not specified.
	 */
	public String getTypeClaim() {
	
		return typ;
	}
	
	
	/**
	 * Sets the type ({@code typ}) claim.
	 *
	 * @param typ The type claim, {@code null} if not specified.
	 */
	public void setTypeClaim(final String typ) {
	
		this.typ = typ;
	}
}
