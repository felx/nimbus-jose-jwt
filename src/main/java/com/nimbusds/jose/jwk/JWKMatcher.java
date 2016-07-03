package com.nimbusds.jose.jwk;


import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import com.nimbusds.jose.Algorithm;
import net.jcip.annotations.Immutable;


/**
 * JSON Web Key (JWK) matcher. May be used to ensure a JWK matches a set of
 * application-specific criteria.
 *
 * <p>Supported key matching criteria:
 *
 * <ul>
 *     <li>Any, unspecified, one or more key types (typ).
 *     <li>Any, unspecified, one or more key uses (use).
 *     <li>Any, unspecified, one or more key operations (key_ops).
 *     <li>Any, unspecified, one or more key algorithms (alg).
 *     <li>Any, unspecified, one or more key identifiers (kid).
 *     <li>Private only key.
 *     <li>Public only key.
 * </ul>
 *
 * <p>Matching by X.509 certificate URL, thumbprint and chain is not supported.
 *
 * @author Vladimir Dzhuvinov
 * @version 2016-07-03
 */
@Immutable
public class JWKMatcher {


	/**
	 * The key types to match.
	 */
	private final Set<KeyType> types;


	/**
	 * The public key uses to match.
	 */
	private final Set<KeyUse> uses;


	/**
	 * The key operations to match.
	 */
	private final Set<KeyOperation> ops;


	/**
	 * The algorithms to match.
	 */
	private final Set<Algorithm> algs;


	/**
	 * The key IDs to match.
	 */
	private final Set<String> ids;


	/**
	 * If {@code true} only private keys are matched.
	 */
	private final boolean privateOnly;


	/**
	 * If {@code true} only public keys are matched.
	 */
	private final boolean publicOnly;


	/**
	 * The minimum key size in bits, zero implies no minimum size limit.
	 */
	private final int minSizeBits;


	/**
	 * The maximum key size in bits, zero implies no maximum size limit.
	 */
	private final int maxSizeBits;


	/**
	 * Builder for constructing JWK matchers.
	 *
	 * <p>Example usage:
	 *
	 * <pre>
	 * JWKMatcher matcher = new JWKMatcher().keyID("123").build();
	 * </pre>
	 */
	public static class Builder {

		
		/**
		 * The key types to match.
		 */
		private Set<KeyType> types;


		/**
		 * The public key uses to match.
		 */
		private Set<KeyUse> uses;


		/**
		 * The key operations to match.
		 */
		private Set<KeyOperation> ops;


		/**
		 * The algorithms to match.
		 */
		private Set<Algorithm> algs;


		/**
		 * The key IDs to match.
		 */
		private Set<String> ids;


		/**
		 * If {@code true} only private keys are matched.
		 */
		private boolean privateOnly = false;


		/**
		 * If {@code true} only public keys are matched.
		 */
		private boolean publicOnly = false;


		/**
		 * The minimum key size in bits, zero implies no minimum size
		 * limit.
		 */
		private int minSizeBits = 0;


		/**
		 * The maximum key size in bits, zero implies no maximum size
		 * limit.
		 */
		private int maxSizeBits = 0;


		/**
		 * Sets a single key type to match.
		 *
		 * @param kty The key type, {@code null} if not specified.
		 *            
		 * @return This builder.            
		 */
		public Builder keyType(final KeyType kty) {

			if (kty == null) {
				types = null;
			} else {
				types = new HashSet<>(Collections.singletonList(kty));
			}
			
			return this;
		}


		/**
		 * Sets multiple key types to match.
		 *
		 * @param types The key types.
		 *
		 * @return This builder.
		 */
		public Builder keyTypes(final KeyType ... types) {

			keyTypes(new HashSet<>(Arrays.asList(types)));
			return this;
		}


		/**
		 * Sets multiple key types to match.
		 *
		 * @param types The key types, {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder keyTypes(final Set<KeyType> types) {

			this.types = types;
			return this;
		}


		/**
		 * Sets a single public key use to match.
		 *
		 * @param use The public key use, {@code null} if not 
		 *            specified.
		 *
		 * @return This builder.
		 */
		public Builder keyUse(final KeyUse use) {

			if (use == null) {
				uses = null;
			} else {
				uses = new HashSet<>(Collections.singletonList(use));
			}
			return this;
		}


		/**
		 * Sets multiple public key uses to match.
		 *
		 * @param uses The public key uses.
		 *
		 * @return This builder.
		 */
		public Builder keyUses(final KeyUse... uses) {

			keyUses(new HashSet<>(Arrays.asList(uses)));
			return this;
		}


		/**
		 * Sets multiple public key uses to match.
		 *
		 * @param uses The public key uses, {@code null} if not
		 *             specified.
		 *
		 * @return This builder.
		 */
		public Builder keyUses(final Set<KeyUse> uses) {

			this.uses = uses;
			return this;
		}


		/**
		 * Sets a single key operation to match.
		 *
		 * @param op The key operation, {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder keyOperation(final KeyOperation op) {

			if (op == null) {
				ops = null;
			} else {
				ops = new HashSet<>(Collections.singletonList(op));
			}
			return this;
		}


		/**
		 * Sets multiple key operations to match.
		 *
		 * @param ops The key operations.
		 *
		 * @return This builder.
		 */
		public Builder keyOperations(final KeyOperation... ops) {

			keyOperations(new HashSet<>(Arrays.asList(ops)));
			return this;
		}


		/**
		 * Sets multiple key operations to match.
		 *
		 * @param ops The key operations, {@code null} if not
		 *            specified.
		 *
		 * @return This builder.
		 */
		public Builder keyOperations(final Set<KeyOperation> ops) {

			this.ops = ops;
			return this;
		}


		/**
		 * Sets a single JOSE algorithm to match.
		 *
		 * @param alg The JOSE algorithm, {@code null} if not
		 *            specified.
		 *
		 * @return This builder.
		 */
		public Builder algorithm(final Algorithm alg) {

			if (alg == null) {
				algs = null;
			} else {
				algs = new HashSet<>(Collections.singletonList(alg));
			}
			return this;
		}


		/**
		 * Sets multiple JOSE algorithms to match.
		 *
		 * @param algs The JOSE algorithms.
		 *
		 * @return This builder.
		 */
		public Builder algorithms(final Algorithm ... algs) {

			algorithms(new HashSet<>(Arrays.asList(algs)));
			return this;
		}


		/**
		 * Sets multiple JOSE algorithms to match.
		 *
		 * @param algs The JOSE algorithms, {@code null} if not
		 *             specified.
		 *
		 * @return This builder.
		 */
		public Builder algorithms(final Set<Algorithm> algs) {

			this.algs = algs;
			return this;
		}


		/**
		 * Sets a single key ID to match.
		 *
		 * @param id The key ID, {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder keyID(final String id) {

			if (id == null) {
				ids = null;
			} else {
				ids = new HashSet<>(Collections.singletonList(id));
			}
			return this;
		}


		/**
		 * Sets multiple key IDs to match.
		 *
		 * @param ids The key IDs.
		 *
		 * @return This builder.
		 */
		public Builder keyIDs(final String ... ids) {

			keyIDs(new HashSet<>(Arrays.asList(ids)));
			return this;
		}


		/**
		 * Sets multiple key IDs to match.
		 *
		 * @param ids The key IDs, {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder keyIDs(final Set<String> ids) {

			this.ids = ids;
			return this;
		}


		/**
		 * Sets the private key matching policy.
		 *
		 * @param privateOnly If {@code true} only private keys are
		 *                    matched.
		 *
		 * @return This builder.
		 */
		public Builder privateOnly(final boolean privateOnly) {

			this.privateOnly = privateOnly;
			return this;
		}


		/**
		 * Sets the public key matching policy.
		 *
		 * @param publicOnly  If {@code true} only public keys are
		 *                    matched.
		 *
		 * @return This builder.
		 */
		public Builder publicOnly(final boolean publicOnly) {

			this.publicOnly = publicOnly;
			return this;
		}


		/**
		 * Sets the minimal key size.
		 *
		 * @param minSizeBits The minimum key size in bits, zero
		 *                    implies no minimum key size limit.
		 *
		 * @return This builder.
		 */
		public Builder minKeySize(final int minSizeBits) {

			this.minSizeBits = minSizeBits;
			return this;
		}


		/**
		 * Sets the maximum key size.
		 *
		 * @param maxSizeBits The maximum key size in bits, zero
		 *                    implies no maximum key size limit.
		 *
		 * @return This builder.
		 */
		public Builder maxKeySize(final int maxSizeBits) {

			this.maxSizeBits = maxSizeBits;
			return this;
		}


		/**
		 * Builds a new JWK matcher.
		 *
		 * @return The JWK matcher.
		 */
		public JWKMatcher build() {

			return new JWKMatcher(types, uses, ops, algs, ids, privateOnly, publicOnly, minSizeBits, maxSizeBits);
		}
	}


	/**
	 * Creates a new JSON Web Key (JWK) matcher.
	 *
	 * @param types       The key types to match, {@code null} if not
	 *                    specified.
	 * @param uses        The public key uses to match, {@code null} if not
	 *                    specified.
	 * @param ops         The key operations to match, {@code null} if not
	 *                    specified.
	 * @param algs        The JOSE algorithms to match, {@code null} if not
	 *                    specified.
	 * @param ids         The key IDs to match, {@code null} if not
	 *                    specified.
	 * @param privateOnly If {@code true} only private keys are
	 *                    matched.
	 * @param publicOnly  If {@code true} only public keys are
	 *                    matched.
	 */
	@Deprecated
	public JWKMatcher(final Set<KeyType> types,
			  final Set<KeyUse> uses,
			  final Set<KeyOperation> ops,
			  final Set<Algorithm> algs,
			  final Set<String> ids,
			  final boolean privateOnly,
			  final boolean publicOnly) {

		this(types, uses, ops, algs, ids, privateOnly, publicOnly, 0, 0);
	}


	/**
	 * Creates a new JSON Web Key (JWK) matcher.
	 *
	 * @param types       The key types to match, {@code null} if not
	 *                    specified.
	 * @param uses        The public key uses to match, {@code null} if not
	 *                    specified.
	 * @param ops         The key operations to match, {@code null} if not
	 *                    specified.
	 * @param algs        The JOSE algorithms to match, {@code null} if not
	 *                    specified.
	 * @param ids         The key IDs to match, {@code null} if not
	 *                    specified.
	 * @param privateOnly If {@code true} only private keys are
	 *                    matched.
	 * @param publicOnly  If {@code true} only public keys are
	 *                    matched.
	 * @param minSizeBits The minimum key size in bits, zero implies no
	 *                    minimum size limit.
	 * @param maxSizeBits The maximum key size in bits, zero implies no
	 *                    maximum size limit.
	 */
	public JWKMatcher(final Set<KeyType> types,
			  final Set<KeyUse> uses,
			  final Set<KeyOperation> ops,
			  final Set<Algorithm> algs,
			  final Set<String> ids,
			  final boolean privateOnly,
			  final boolean publicOnly,
			  final int minSizeBits,
			  final int maxSizeBits) {

		this.types = types;
		this.uses = uses;
		this.ops = ops;
		this.algs = algs;
		this.ids = ids;
		this.privateOnly = privateOnly;
		this.publicOnly = publicOnly;
		this.minSizeBits = minSizeBits;
		this.maxSizeBits = maxSizeBits;
	}


	/**
	 * Returns the key types to match.
	 *
	 * @return The key types, {@code null} if not specified.
	 */
	public Set<KeyType> getKeyTypes() {

		return types;
	}


	/**
	 * Returns the public key uses to match.
	 *
	 * @return The public key uses, {@code null} if not specified.
	 */
	public Set<KeyUse> getKeyUses() {

		return uses;
	}


	/**
	 * Returns the key operations to match.
	 *
	 * @return The key operations, {@code null} if not specified.
	 */
	public Set<KeyOperation> getKeyOperations() {

		return ops;
	}


	/**
	 * Returns the JOSE algorithms to match.
	 *
	 * @return The JOSE algorithms, {@code null} if not specified.
	 */
	public Set<Algorithm> getAlgorithms() {

		return algs;
	}


	/**
	 * Returns the key IDs to match.
	 *
	 * @return The key IDs, {@code null} if not specified.
	 */
	public Set<String> getKeyIDs() {

		return ids;
	}


	/**
	 * Returns {@code true} if only private keys are matched.
	 *
	 * @return {@code true} if only private keys are matched, else 
	 *         {@code false}.
	 */
	public boolean isPrivateOnly() {

		return privateOnly;
	}


	/**
	 * Returns {@code true} if only public keys are matched.
	 *
	 * @return {@code true} if only public keys are selected, else
	 *         {@code false}.
	 */
	public boolean isPublicOnly() {

		return publicOnly;
	}


	/**
	 * Returns the minimum key size.
	 *
	 * @return The minimum key size in bits, zero implies no minimum size
	 *         limit.
	 */
	public int getMinSize() {

		return minSizeBits;
	}


	/**
	 * Returns the maximum key size.
	 *
	 * @return The maximum key size in bits, zero implies no maximum size
	 *         limit.
	 */
	public int getMaxSize() {

		return maxSizeBits;
	}


	/**
	 * Returns {@code true} if the specified JWK matches.
	 *
	 * @param key The JSON Web Key (JWK). Must not  be {@code null}.
	 *
	 * @return {@code true} if the JWK matches, else {@code false}.
	 */
	public boolean matches(final JWK key) {

		if (privateOnly && ! key.isPrivate())
			return false;

		if (publicOnly && key.isPrivate())
			return false;

		if (types != null && ! types.contains(key.getKeyType()))
			return false;

		if (uses != null && ! uses.contains(key.getKeyUse()))
			return false;

		if (ops != null) {

			if (ops.contains(null) && key.getKeyOperations() == null) {
				// pass
			} else if (key.getKeyOperations() != null && ops.containsAll(key.getKeyOperations())) {
				// pass
			} else {
				return false;
			}
		}

		if (algs != null && ! algs.contains(key.getAlgorithm()))
			return false;

		if (ids != null && ! ids.contains(key.getKeyID()))
			return false;

		if (minSizeBits > 0) {

			if (key.size() < minSizeBits)
				return false;
		}

		if (maxSizeBits > 0) {

			if (key.size() > maxSizeBits)
				return false;
		}

		return true;
	}
}
