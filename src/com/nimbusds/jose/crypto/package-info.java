/**
 * Implementations of selected standard Javascript Object Signing and Encryption
 * (JOSE) algorithms.
 *
 * <p>Provides {@link com.nimbusds.jose.sdk.JWSSigner signers} and 
 * {@link com.nimbusds.jose.sdk.JWSVerifier verifiers} for the following JSON
 * Web Signature (JWS) algorithms:
 *
 * <ul>
 *     <li>For HMAC signature algorithms HS256, HS384 and HS512:
 *         <ul>
 *             <li>{@link com.nimbusds.jose.crypto.MACSigner}
 *             <li>{@link com.nimbusds.jose.crypto.MACVerifier}
 *         </ul>
 *     <li>For RSA-SSA signature algorithms RS256, RS384 and RS512:
 *         <ul>
 *             <li>{@link com.nimbusds.jose.crypto.RSASSASigner}
 *             <li>{@link com.nimbusds.jose.crypto.RSASSAVerifier}
 *         </ul>
 *      <li>For ECDSA signature algorithms ES256, ES384 and ES512:
 *         <ul>
 *             <li>{@link com.nimbusds.jose.crypto.ECDSASigner}
 *             <li>{@link com.nimbusds.jose.crypto.ECDSAVerifier}
 *         </ul>
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ ($version-date$)
 */
package com.nimbusds.jose.crypto;
