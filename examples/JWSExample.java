import java.text.ParseException;

import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACValidator;

import com.nimbusds.jose.sdk.JOSEException;
import com.nimbusds.jose.sdk.JWSAlgorithm;
import com.nimbusds.jose.sdk.JWSHeader;
import com.nimbusds.jose.sdk.JWSObject;
import com.nimbusds.jose.sdk.JWSSigner;
import com.nimbusds.jose.sdk.JWSValidator;
import com.nimbusds.jose.sdk.Payload;


/**
 * Example use of JWS objects.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-03)
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
		
		JWSValidator validator = new MACValidator(sharedKey.getBytes());
		
		boolean validSignature = false;
		
		try {
			validSignature = jwsObject.validator(validator);
			
		} catch (JOSEException e) {
		
			System.err.println("Couldn't check validity of signature: " + e.getMessage());
		}
		
		if (validSignature) {
		
			System.out.println("Valid JWS signature!");
		}
		else {
			System.out.println("Invalid JWS signature!");
			return;
		}
		
		
		System.out.println("Recovered payload message: " + jwsObject.getPayload());
	}
}
