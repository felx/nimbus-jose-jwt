import java.text.ParseException;

import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;


/**
 * Example use of JWS objects.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-23)
 */
public class JWSExample {


	public static void main(final String[] args) {

		// Create payload
		String message = "Hello world!";
		
		Payload payload = new Payload(message);
		
		System.out.println("JWS payload message: " + message);
		
		
		// Create JWS header with HS256 algorithm
		JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);
		header.setContentType("text/plain");
		
		System.out.println("JWS header: " + header.toJSONObject());
		
		
		// Create JWS object
		JWSObject jwsObject = new JWSObject(header, payload);
		
		
		// Create HMAC signer
		String sharedKey = "a0a2abd8-6162-41c3-83d6-1cf559b46afc";
		
		System.out.println("HMAC key: " + sharedKey);
		
		JWSSigner signer = new MACSigner(sharedKey.getBytes());
		
		try {
			jwsObject.sign(signer);
			
		} catch (JOSEException e) {
		
			System.err.println("Couldn't sign JWS object: " + e.getMessage());
			return;
		}
		
		
		// Serialise JWS object to compact format
		String s = jwsObject.serialize();
		
		System.out.println("Serialised JWS object: " + s);
		
		
		
		// Parse back and check signature
		
		try {
			jwsObject = JWSObject.parse(s);
			
		} catch (ParseException e) {
		
			System.err.println("Couldn't parse JWS object: " + e.getMessage());
			return;
		}
		
		System.out.println("JWS object successfully parsed");
		
		JWSVerifier verifier = new MACVerifier(sharedKey.getBytes());
		
		boolean verifiedSignature = false;
		
		try {
			verifiedSignature = jwsObject.verify(verifier);
			
		} catch (JOSEException e) {
		
			System.err.println("Couldn't verify signature: " + e.getMessage());
		}
		
		if (verifiedSignature) {
		
			System.out.println("Verified JWS signature!");
		}
		else {
			System.out.println("Bad JWS signature!");
			return;
		}
		
		
		System.out.println("Recovered payload message: " + jwsObject.getPayload());
	}
}
