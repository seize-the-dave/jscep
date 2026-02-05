package org.jscep.message;

/**
 * ASN.1 encoding types for CMS structures.
 * <p>
 * Some SCEP servers require definite-length encoding for compatibility.
 * The default behavior uses indefinite-length BER encoding.
 */
public enum AsnEncoding {
    /**
     * Basic Encoding Rules with indefinite-length encoding.
     * This is the default and most flexible encoding.
     */
    BER("BER"),

    /**
     * Definite-length BER encoding.
     * Use this when the recipient requires fixed-length encoding.
     */
    DL("DL"),

    /**
     * Distinguished Encoding Rules.
     * The strictest encoding, always uses definite-length.
     */
    DER("DER");

    private final String encoding;

    AsnEncoding(final String encoding) {
        this.encoding = encoding;
    }

    /**
     * Returns the encoding identifier string.
     *
     * @return the encoding identifier
     */
    public String getEncoding() {
        return encoding;
    }
}
