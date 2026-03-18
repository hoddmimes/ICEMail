package org.bouncycastle.asn1.gnu;

/**
 * Shim: bcpg-jdk18on Java-8 bytecode references the old non-internal path
 * org.bouncycastle.asn1.gnu.GNUObjectIdentifiers, but bcprov-jdk18on
 * only ships this class at org.bouncycastle.internal.asn1.gnu.*.
 * This shim extends the internal class to make it visible at the old path.
 */
public interface GNUObjectIdentifiers
        extends org.bouncycastle.internal.asn1.gnu.GNUObjectIdentifiers {
}
