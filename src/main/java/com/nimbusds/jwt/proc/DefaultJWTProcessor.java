package com.nimbusds.jwt.proc;


import java.text.ParseException;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.BaseJOSEProcessor;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.*;


/**
 *
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-06-30
 */
public class DefaultJWTProcessor<C extends SecurityContext>
	extends BaseJOSEProcessor<C>
	implements JWTProcessor<ReadOnlyJWTClaimsSet, C> {


	@Override
	public ReadOnlyJWTClaimsSet process(final String jwtString, final C context)
		throws ParseException, BadJOSEException, JOSEException {

		JWT jwt = JWTParser.parse(jwtString);

		if (jwt instanceof SignedJWT) {
			return process((SignedJWT)jwt, context);
		}

		if (jwt instanceof EncryptedJWT) {
			return process((EncryptedJWT)jwt, context);
		}

		if (jwt instanceof PlainJWT) {
			return process((PlainJWT)jwt, context);
		}

		// Should never happen
		throw new JOSEException("Unexpected JWT object type: " + jwt.getClass());
	}


	@Override
	public ReadOnlyJWTClaimsSet process(final PlainJWT plainJWT, final C context)
		throws BadJOSEException, JOSEException {

		return null;
	}


	@Override
	public ReadOnlyJWTClaimsSet process(final SignedJWT signedJWT, final C context)
		throws BadJOSEException, JOSEException {

		return null;
	}


	@Override
	public ReadOnlyJWTClaimsSet process(final EncryptedJWT encryptedJWT, final C context)
		throws BadJOSEException, JOSEException {

		return null;
	}
}
