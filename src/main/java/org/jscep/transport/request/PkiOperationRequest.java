package org.jscep.transport.request;

import java.io.IOException;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.cms.CMSSignedData;
import org.jscep.message.AsnEncoding;

/**
 * The {@code PkiOperationRequest} class may represent a {@code PKCSReq},
 * {@code GetCertInitial}, {@code GetCert} and {@code GetCRL} request.
 */
public final class PkiOperationRequest extends Request {
    private final CMSSignedData msgData;
    private final AsnEncoding asnEncoding;

    /**
     * Creates a new {@code PkiOperationRequest} for the given
     * {@code signedData}
     *
     * @param msgData
     *            the pkiMessage to use.
     */
    public PkiOperationRequest(final CMSSignedData msgData) {
        this(msgData, AsnEncoding.BER);
    }

    /**
     * Creates a new {@code PkiOperationRequest} for the given
     * {@code signedData} with specified ASN.1 encoding.
     *
     * @param msgData
     *            the pkiMessage to use.
     * @param asnEncoding
     *            the ASN.1 encoding type to use.
     */
    public PkiOperationRequest(final CMSSignedData msgData,
                               final AsnEncoding asnEncoding) {
        super(Operation.PKI_OPERATION);

        this.msgData = msgData;
        this.asnEncoding = asnEncoding;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getMessage() {
        try {
            return new String(Base64.encodeBase64(
                    msgData.getEncoded(asnEncoding.getEncoding()), false), "UTF-8");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString() {
        return msgData.toString();
    }
}
