package com.nimbusds.jose.util;

import net.jcip.annotations.NotThreadSafe;

/**
 * Generic container of items of any type.
 * <p>
 * This class is not thread-safe, if thread safety is required it should be done
 * externally to the class.
 * <p>
 * The author believes he borrowed the idea for such a class many years ago from a man called Boris Karadjov.
 *
 * @param <T> the type of the item in this container.
 */
@NotThreadSafe
public class Container<T> {
    private T item;

    public Container() {
    }

    public Container(T item) {
	this.item = item;
    }

    public T get() {
	return item;
    }

    public void set(T item) {
	this.item = item;
    }
}