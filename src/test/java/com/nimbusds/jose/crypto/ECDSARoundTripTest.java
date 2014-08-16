package com.nimbusds.jose.crypto;


import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.Arrays;
import java.util.HashSet;

import junit.framework.TestCase;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.util.Base64URL;


/**
 * Tests round-trip ES256, EC384 and EC512 JWS signing and verification.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-07-10)
 */
public class ECDSARoundTripTest extends TestCase {


	private static final int COFACTOR = 1;


	public static final ECParameterSpec EC256SPEC = new ECParameterSpec(
		new EllipticCurve(
			new ECFieldFp(new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853951")),
			new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853948"),
			new BigInteger("41058363725152142129326129780047268409114441015993725554835256314039467401291")),
		new ECPoint(
			new BigInteger("48439561293906451759052585252797914202762949526041747995844080717082404635286"),
			new BigInteger("36134250956749795798585127919587881956611106672985015071877198253568414405109")),
		new BigInteger("115792089210356248762697446949407573529996955224135760342422259061068512044369"),
		COFACTOR);


	private static final ECParameterSpec EC384SPEC = new ECParameterSpec(
		new EllipticCurve(
			new ECFieldFp(new BigInteger("39402006196394479212279040100143613805079739270465" +
				                     "44666794829340424572177149687032904726608825893800" +
				                     "1861606973112319")),
			new BigInteger("39402006196394479212279040100143613805079739270465" +
				       "44666794829340424572177149687032904726608825893800" +
				       "1861606973112316"),
			new BigInteger("27580193559959705877849011840389048093056905856361" +
				       "56852142870730198868924130986086513626076488374510" +
				       "7765439761230575")
        		),
		new ECPoint(
			new BigInteger("26247035095799689268623156744566981891852923491109" +
				       "21338781561590092551885473805008902238805397571978" +
				       "6650872476732087"),
			new BigInteger("83257109614890299855467512895201081792878530488613" +
				       "15594709205902480503199884419224438643760392947333" +
				       "078086511627871")
			),
		new BigInteger("39402006196394479212279040100143613805079739270465446667946905279627" +
		               "659399113263569398956308152294913554433653942643"),
		COFACTOR);


	public static final ECParameterSpec EC512SPEC = new ECParameterSpec(
		new EllipticCurve(
			new ECFieldFp(new BigInteger("68647976601306097149819007990813932172694353001433" +
				                     "05409394463459185543183397656052122559640661454554" +
				                     "97729631139148085803712198799971664381257402829111" +
				                     "5057151")),
			new BigInteger("68647976601306097149819007990813932172694353001433" +
				       "05409394463459185543183397656052122559640661454554" +
				       "97729631139148085803712198799971664381257402829111" +
				       "5057148"),
			new BigInteger("10938490380737342745111123907668055699362075989516" +
				       "83748994586394495953116150735016013708737573759623" +
				       "24859213229670631330943845253159101291214232748847" +
				       "8985984")
			),
		new ECPoint(
			new BigInteger("26617408020502170632287687167233609607298591687569" +
				       "73147706671368418802944996427808491545080627771902" +
				       "35209424122506555866215711354557091681416163731589" +
				       "5999846"),
			new BigInteger("37571800257700204635455072244911836035944551347697" +
				       "62486694567779615544477440556316691234405012945539" +
				       "56214444453728942852258566672919658081012434427757" +
				       "8376784")
			),
		new BigInteger("68647976601306097149819007990813932172694353001433" +
                               "05409394463459185543183397655394245057746333217197" +
                               "53296399637136332111386476861244038034037280889270" +
                               "7005449"),
		COFACTOR);


	private static KeyPair createECKeyPair(AlgorithmParameterSpec spec) 
		throws Exception {

		// Create the public and private keys
		KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("EC");
		keyGenerator.initialize(spec);
		KeyPair keyPair = keyGenerator.generateKeyPair();

		return keyPair;
	}


	private static JWSObject createInitialJWSObject(final JWSAlgorithm alg) {

		JWSHeader header = new JWSHeader.Builder(alg).
			contentType("text/plain").
			build();

		return new JWSObject(header, new Payload("Hello world!"));
	}


	public void testES256()
		throws Exception {

		// Create the public and private keys
		KeyPair keyPair = createECKeyPair(EC256SPEC);
		ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
		ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();

		// Creates initial unsigned JWS object
		JWSObject jwsObject = createInitialJWSObject(JWSAlgorithm.ES256);

		// Initialise signer
		JWSSigner signer = new ECDSASigner(privateKey.getS());

		jwsObject.sign(signer);

		assertEquals(JWSObject.State.SIGNED, jwsObject.getState());

		// Initialise verifier
		BigInteger x = publicKey.getW().getAffineX();
		BigInteger y = publicKey.getW().getAffineY();
		JWSVerifier verifier = new ECDSAVerifier(x, y);

		boolean verified = jwsObject.verify(verifier);

		assertTrue("EC256 signature verified", verified);
	}


	public void testES384()
		throws Exception {

		// Create the public and private keys
		KeyPair keyPair = createECKeyPair(EC384SPEC);
		ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
		ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();

		// Creates initial unsigned JWS object
		JWSObject jwsObject = createInitialJWSObject(JWSAlgorithm.ES384);

		// Initialise signer
		JWSSigner signer = new ECDSASigner(privateKey.getS());

		jwsObject.sign(signer);

		assertEquals(JWSObject.State.SIGNED, jwsObject.getState());

		// Initialise verifier
		BigInteger x = publicKey.getW().getAffineX();
		BigInteger y = publicKey.getW().getAffineY();
		JWSVerifier verifier = new ECDSAVerifier(x, y);

		boolean verified = jwsObject.verify(verifier);

		assertTrue("EC384 signature verified", verified);
	}


	public void testES512()
		throws Exception {

		// Create the public and private keys
		KeyPair keyPair = createECKeyPair(EC512SPEC);
		ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
		ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();

		// Creates initial unsigned JWS object
		JWSObject jwsObject = createInitialJWSObject(JWSAlgorithm.ES512);

		// Initialise signer
		JWSSigner signer = new ECDSASigner(privateKey.getS());

		jwsObject.sign(signer);

		assertEquals(JWSObject.State.SIGNED, jwsObject.getState());

		// Initialise verifier
		BigInteger x = publicKey.getW().getAffineX();
		BigInteger y = publicKey.getW().getAffineY();
		JWSVerifier verifier = new ECDSAVerifier(x, y);

		boolean verified = jwsObject.verify(verifier);

		assertTrue("EC512 signature verified", verified);
	}


	public void testCritHeaderParamIgnore()
		throws Exception {

		JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES512).
			customParameter("exp", "2014-04-24").
			criticalHeaders(new HashSet<String>(Arrays.asList("exp"))).
			build();

		KeyPair keyPair = createECKeyPair(EC512SPEC);
		ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
		ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();

		JWSObject jwsObject = new JWSObject(header, new Payload("Hello world!"));

		JWSSigner signer = new ECDSASigner(privateKey.getS());

		jwsObject.sign(signer);

		assertEquals(JWSObject.State.SIGNED, jwsObject.getState());

		BigInteger x = publicKey.getW().getAffineX();
		BigInteger y = publicKey.getW().getAffineY();
		JWSVerifier verifier = new ECDSAVerifier(x, y);
		verifier.getIgnoredCriticalHeaderParameters().add("exp");

		boolean verified = jwsObject.verify(verifier);

		assertTrue("Verified signature", verified);

		assertEquals("State check", JWSObject.State.VERIFIED, jwsObject.getState());
	}


	public void testCritHeaderParamReject()
		throws Exception {

		JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES512).
			customParameter("exp", "2014-04-24").
			criticalHeaders(new HashSet<String>(Arrays.asList("exp"))).
			build();

		KeyPair keyPair = createECKeyPair(EC512SPEC);
		ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
		ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();

		JWSObject jwsObject = new JWSObject(header, new Payload("Hello world!"));

		JWSSigner signer = new ECDSASigner(privateKey.getS());

		jwsObject.sign(signer);

		assertEquals(JWSObject.State.SIGNED, jwsObject.getState());

		BigInteger x = publicKey.getW().getAffineX();
		BigInteger y = publicKey.getW().getAffineY();
		JWSVerifier verifier = new ECDSAVerifier(x, y);

		boolean verified = jwsObject.verify(verifier);

		assertFalse("Verified signature", verified);

		assertEquals("State check", JWSObject.State.SIGNED, jwsObject.getState());
	}
}
