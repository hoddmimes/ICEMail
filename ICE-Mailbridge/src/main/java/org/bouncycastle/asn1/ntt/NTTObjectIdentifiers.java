package org.bouncycastle.asn1.ntt;

/**
 * Shim: bcpg-jdk18on Java-8 bytecode references the old non-internal path
 * org.bouncycastle.asn1.ntt.NTTObjectIdentifiers, but bcprov-jdk18on
 * only ships this class at org.bouncycastle.internal.asn1.ntt.*.
 * This shim extends the internal class to make it visible at the old path.
 */
public interface NTTObjectIdentifiers
        extends org.bouncycastle.internal.asn1.ntt.NTTObjectIdentifiers {
}
