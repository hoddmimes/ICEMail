package org.bouncycastle.asn1.cryptlib;

/**
 * Shim: bcpg-jdk18on Java-8 bytecode references the old non-internal path
 * org.bouncycastle.asn1.cryptlib.CryptlibObjectIdentifiers, but bcprov-jdk18on
 * only ships this class at org.bouncycastle.internal.asn1.cryptlib.*.
 * This shim extends the internal class to make it visible at the old path.
 */
public class CryptlibObjectIdentifiers
        extends org.bouncycastle.internal.asn1.cryptlib.CryptlibObjectIdentifiers {
}
