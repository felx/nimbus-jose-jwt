package com.nimbusds.jose;


import java.util.Collection;
import java.util.LinkedHashSet;

import net.jcip.annotations.Immutable;


/**
 * Algorithm family.
 *
 * @author Vladimir Dzhuvinov
 * @version 2016-08-24
 */
@Immutable
class AlgorithmFamily <T extends Algorithm> extends LinkedHashSet<T> {


	private static final long serialVersionUID = 1L;


	/**
	 * Creates a new algorithm family.
	 *
	 * @param algs The algorithms of the family. Must not be {@code null}.
	 */
	public AlgorithmFamily(final T ... algs) {
		for (T alg: algs) {
			super.add(alg);
		}
	}


	@Override
	public boolean add(final T alg) {
		throw new UnsupportedOperationException();
	}


	@Override
	public boolean addAll(final Collection<? extends T> algs) {
		throw new UnsupportedOperationException();
	}


	@Override
	public boolean remove(final Object o) {
		throw new UnsupportedOperationException();
	}


	@Override
	public boolean removeAll(final Collection<?> c) {
		throw new UnsupportedOperationException();
	}


	@Override
	public boolean retainAll(final Collection<?> c) {
		throw new UnsupportedOperationException();
	}
}
