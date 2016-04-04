/**
 * Implementations of all standard Javascript Object Signing and Encryption
 * (JOSE) algorithms.
 *
 * <p>Provides {@link com.nimbusds.jose.JWSSigner signers} and 
 * {@link com.nimbusds.jose.JWSVerifier verifiers} for the following JSON Web
 * Signature (JWS) algorithms:
 *
 * <ul>
 *     <li>For HMAC algorithms HS256, HS384 and HS512:
 *         <ul>
 *             <li>{@link com.nimbusds.jose.crypto.MACSigner}
 *             <li>{@link com.nimbusds.jose.crypto.MACVerifier}
 *         </ul>
 *     <li>For RSA-SSA signatures RS256, RS384, RS512, PS256, PS384 and PS512:
 *         <ul>
 *             <li>{@link com.nimbusds.jose.crypto.RSASSASigner}
 *             <li>{@link com.nimbusds.jose.crypto.RSASSAVerifier}
 *         </ul>
 *      <li>For ECDSA signatures ES256, ES384 and ES512:
 *         <ul>
 *             <li>{@link com.nimbusds.jose.crypto.ECDSASigner}
 *             <li>{@link com.nimbusds.jose.crypto.ECDSAVerifier}
 *         </ul>
 * </ul>
 *
 * <p>Provides {@link com.nimbusds.jose.JWEEncrypter encrypters} and 
 * {@link com.nimbusds.jose.JWEDecrypter decrypters} for the following JSON
 * Web Encryption (JWE) algorithms:
 *
 * <ul>
 *     <li>For RSA PKCS#1 v1.5 and RSA OAEP:
 *         <ul>
 *             <li>{@link com.nimbusds.jose.crypto.RSAEncrypter}
 *             <li>{@link com.nimbusds.jose.crypto.RSADecrypter}
 *         </ul>
 *     <li>For AES key wrap and AES GCM key encryption:
 *         <ul>
 *             <li>{@link com.nimbusds.jose.crypto.AESEncrypter}
 *             <li>{@link com.nimbusds.jose.crypto.AESDecrypter}
 *         </ul>
 *     <li>For direct encryption (using a shared symmetric key):
 *         <ul>
 *             <li>{@link com.nimbusds.jose.crypto.DirectEncrypter}
 *             <li>{@link com.nimbusds.jose.crypto.DirectDecrypter}
 *         </ul>
 *     <li>For Elliptic Curve Diffie-Hellman (ECDH) encryption:
 *         <ul>
 *             <li>{@link com.nimbusds.jose.crypto.ECDHEncrypter}
 *             <li>{@link com.nimbusds.jose.crypto.ECDHDecrypter}
 *         </ul>
 *     <li>For password-based (PBKDF2) encryption:
 *         <ul>
 *             <li>{@link com.nimbusds.jose.crypto.PasswordBasedEncrypter}
 *             <li>{@link com.nimbusds.jose.crypto.PasswordBasedDecrypter}
 *         </ul>
 * </ul>
 *
 * <p>References:
 *
 * <ul>
 *     <li><a href="http://tools.ietf.org/html/rfc7518">RFC 7518 (JWA)</a>
 * </ul>
 */
package com.nimbusds.jose.crypto;
