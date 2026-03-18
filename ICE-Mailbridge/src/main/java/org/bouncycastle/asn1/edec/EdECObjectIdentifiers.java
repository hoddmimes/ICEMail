package org.bouncycastle.asn1.edec;

/**
 * Shim: bcpg-jdk18on Java-8 bytecode references the old non-internal path
 * org.bouncycastle.asn1.edec.EdECObjectIdentifiers, but bcprov-jdk18on
 * only ships this class at org.bouncycastle.internal.asn1.edec.*.
 * This shim extends the internal class to make it visible at the old path.
 */
public interface EdECObjectIdentifiers
        extends org.bouncycastle.internal.asn1.edec.EdECObjectIdentifiers {
}
