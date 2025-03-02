package org.jscep.transport;

import java.math.BigInteger;
import java.net.Proxy;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import junit.framework.Assert;

import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.x500.X500Name;
import org.eclipse.jetty.server.Server;
import org.jscep.message.GetCert;
import org.jscep.message.PkcsPkiEnvelopeEncoder;
import org.jscep.message.PkiMessageEncoder;
import org.jscep.transaction.Nonce;
import org.jscep.transaction.TransactionId;
import org.jscep.transport.request.PkiOperationRequest;
import org.jscep.transport.response.PkiOperationResponseHandler;
import org.jscep.util.X509Certificates;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

abstract public class AbstractTransportTest {
    protected static URL URL;
    protected static Proxy PROXY;
    protected Transport transport;
    private static Server SERVER;

    @BeforeClass
    public static void serverStart() throws Exception {
        SERVER = new Server(0);
        SERVER.start();

        URL = SERVER.getURI().toURL();
        PROXY = Proxy.NO_PROXY;
    }

    @Before
    public void setUp() throws Exception {
        transport = getTransport(URL);
    }

    @AfterClass
    public static void serverStop() throws Exception {
        SERVER.stop();
    }

    abstract protected Transport getTransport(URL url);

    @Test
    public void test404() throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        PkcsPkiEnvelopeEncoder envEnc = new PkcsPkiEnvelopeEncoder(
                getCertificate(keyPair), "DES");
        PkiMessageEncoder enc = new PkiMessageEncoder(keyPair.getPrivate(),
                getCertificate(keyPair), envEnc);

        TransactionId transId = TransactionId.createTransactionId();
        Nonce senderNonce = Nonce.nextNonce();
        X500Name name = new X500Name("CN=jscep.org");
        BigInteger serialNumber = BigInteger.ONE;
        IssuerAndSerialNumber iasn = new IssuerAndSerialNumber(name,
                serialNumber);
        GetCert getCert = new GetCert(transId, senderNonce, iasn);
        PkiOperationRequest req = new PkiOperationRequest(enc.encode(getCert));

        try {
            transport.sendRequest(req, new PkiOperationResponseHandler());
        } catch (TransportException e) {
            Assert.assertEquals("404 Not Found", e.getMessage());
        }
    }

    private X509Certificate getCertificate(KeyPair keyPair)
            throws GeneralSecurityException {
        final X500Principal subject = new X500Principal("CN=example.org");

        return X509Certificates.createEphemeral(subject, keyPair);
    }
}
