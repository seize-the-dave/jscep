package org.jscep.message;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.util.Store;
import org.jscep.asn1.IssuerAndSubject;
import org.jscep.transaction.FailInfo;
import org.jscep.transaction.Nonce;
import org.jscep.transaction.TransactionId;
import org.jscep.util.X509Certificates;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import junit.framework.Assert;

@RunWith(Parameterized.class)
public class PkiMessageEncoderTest {
    @Parameters
    public static Collection<Object[]> getParameters() throws Exception {
        List<Object[]> params = new ArrayList<Object[]>();

        KeyPair pair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        TransactionId transId = TransactionId.createTransactionId();
        Nonce recipientNonce = Nonce.nextNonce();
        Nonce senderNonce = recipientNonce;
        X500Name issuer = new X500Name("CN=CA");
        X500Name subject = new X500Name("CN=Client");
        IssuerAndSubject ias = new IssuerAndSubject(issuer, subject);
        BigInteger serial = BigInteger.ONE;
        IssuerAndSerialNumber iasn = new IssuerAndSerialNumber(issuer, serial);
        PKCS10CertificationRequest csr = getCsr(new X500Principal("CN=Client"),
                pair.getPublic(), pair.getPrivate(), "password".toCharArray());
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA")
                .build(pair.getPrivate());
        X509Certificate cert = X509Certificates.createEphemeral(
                new X500Principal("CN=client"), pair);
        Store<?> certs = new JcaCertStore(Collections.singleton(cert));
        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder().build()).build(
                sha1Signer, cert));
        gen.addCertificates(certs);
        CMSTypedData msg = new CMSAbsentContent();
        CMSSignedData sigData = gen.generate(msg, false);

        params.add(new Object[] { new GetCert(transId, senderNonce, iasn) });
        params.add(new Object[] { new GetCertInitial(transId, senderNonce, ias) });
        params.add(new Object[] { new GetCrl(transId, senderNonce, iasn) });
        params.add(new Object[] { new PkcsReq(transId, senderNonce, csr) });
        params.add(new Object[] { new CertRep(transId, senderNonce,
                recipientNonce) });
        params.add(new Object[] { new CertRep(transId, senderNonce,
                recipientNonce, sigData) });
        params.add(new Object[] { new CertRep(transId, senderNonce,
                recipientNonce, FailInfo.badAlg) });

        return params;
    }

    private final PkiMessage<?> message;

    public PkiMessageEncoderTest(PkiMessage<?> message) {
        this.message = message;
    }

    @Test
    public void simpleTestDES() throws Exception {
    	PkiMessage<?> actual = encodeAndDecodeEnvelope("DES");
        assertEquals(message, actual);
    }
    
    @Test
    public void simpleTestTripleDES() throws Exception {
    	PkiMessage<?> actual = encodeAndDecodeEnvelope("DESede");
        assertEquals(message, actual);
    }
    
    @Test
    public void simpleTestAES192() throws Exception {
    	PkiMessage<?> actual = encodeAndDecodeEnvelope("AES_192");
        assertEquals(message, actual);
    }
    
    @Test
    public void simpleTestAES256() throws Exception {
    	PkiMessage<?> actual = encodeAndDecodeEnvelope("AES_256");
        assertEquals(message, actual);
    }
    
    @Test
    public void simpleTestAES128() throws Exception {
    	PkiMessage<?> actual = encodeAndDecodeEnvelope("AES_128");
        assertEquals(message, actual);
    }

    @Test
    public void simpleTestAES() throws Exception {
        PkiMessage<?> actual = encodeAndDecodeEnvelope("AES");
        assertEquals(message, actual);
    }

    @Test
    public void simpleTestDefiniteLength() throws Exception {
        PkiMessage<?> actual = encodeAndDecodeEnvelope("DES", AsnEncoding.DL);
        assertEquals(message, actual);
    }

    @Test
    public void simpleTestDER() throws Exception {
        PkiMessage<?> actual = encodeAndDecodeEnvelope("DES", AsnEncoding.DER);
        assertEquals(message, actual);
    }

    @Test
    public void invalidSignatureTest() throws Exception {
        KeyPair caPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        X509Certificate ca = X509Certificates.createEphemeral(
                new X500Principal("CN=CA"), caPair);

        KeyPair clientPair = KeyPairGenerator.getInstance("RSA")
                .generateKeyPair();
        X509Certificate client = X509Certificates.createEphemeral(
                new X500Principal("CN=Client"), clientPair);

        // Everything below this line only available to client
        PkcsPkiEnvelopeEncoder envEncoder = new PkcsPkiEnvelopeEncoder(ca,
                "DES");
        PkiMessageEncoder encoder = new PkiMessageEncoder(
                clientPair.getPrivate(), client, envEncoder);

        PkcsPkiEnvelopeDecoder envDecoder = new PkcsPkiEnvelopeDecoder(ca,
                caPair.getPrivate());

        PkiMessageDecoder decoder = new PkiMessageDecoder(client, envDecoder);

        CMSSignedData encodedMessage = encoder.encode(message);

        // modifify the signature
        CMSSignedData encodedMessage2 = modifySignature(encodedMessage);
        try{
            decoder.decode(encodedMessage2);
            Assert.fail("decoding exception expected");
        }catch(MessageDecodingException e)
        {
            assertEquals("decoding exception", "pkiMessage verification failed.", e.getMessage());
        }
    }

    private static PKCS10CertificationRequest getCsr(X500Principal subject,
            PublicKey pubKey, PrivateKey priKey, char[] password)
            throws IOException {
        DERPrintableString cpSet = new DERPrintableString(new String(password));
        SubjectPublicKeyInfo pkInfo = SubjectPublicKeyInfo.getInstance(pubKey
                .getEncoded());

        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(
                "SHA1withRSA");
        ContentSigner signer;
        try {
            signer = signerBuilder.build(priKey);
        } catch (OperatorCreationException e) {
            IOException ioe = new IOException();
            ioe.initCause(e);

            throw ioe;
        }

        PKCS10CertificationRequestBuilder builder = new PKCS10CertificationRequestBuilder(
                X500Name.getInstance(subject.getEncoded()), pkInfo);
        builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_challengePassword,
                cpSet);

        return builder.build(signer);
    }

    private static CMSSignedData modifySignature(CMSSignedData sd)
    throws CMSException
    {
        ContentInfo ci = sd.toASN1Structure();
        SignedData content = (SignedData) ci.getContent();
        SignerInfo si = (SignerInfo) content.getSignerInfos().getObjectAt(0);

        byte[] signature = si.getEncryptedDigest().getOctets();
        int index = signature.length - 10;
        signature[index] = (byte) (signature[index] + 1);

        ASN1OctetString signature2 = new DEROctetString(signature);
        SignerInfo si2 = new SignerInfo(
                si.getSID(),
                si.getDigestAlgorithm(),
                si.getAuthenticatedAttributes(),
                si.getDigestEncryptionAlgorithm(),
                signature2,
                si.getUnauthenticatedAttributes());
        ASN1Set signerInfos2 = new DERSet(si2);

        SignedData content2 = new SignedData(
                content.getDigestAlgorithms(),
                content.getEncapContentInfo(),
                content.getCertificates(),
                content.getCRLs(),
                signerInfos2);

        ContentInfo ci2 = new ContentInfo(ci.getContentType(), content2);
        return new CMSSignedData(ci2);
    }
    
    public PkiMessage<?> encodeAndDecodeEnvelope(String cipherAlgorithm) throws Exception {
        return encodeAndDecodeEnvelope(cipherAlgorithm, AsnEncoding.BER);
    }

    public PkiMessage<?> encodeAndDecodeEnvelope(String cipherAlgorithm,
            AsnEncoding asnEncoding) throws Exception {
        KeyPair caPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        X509Certificate ca = X509Certificates.createEphemeral(
                new X500Principal("CN=CA"), caPair);

        KeyPair clientPair = KeyPairGenerator.getInstance("RSA")
                .generateKeyPair();
        X509Certificate client = X509Certificates.createEphemeral(
                new X500Principal("CN=Client"), clientPair);

        // Everything below this line only available to client
        PkcsPkiEnvelopeEncoder envEncoder = new PkcsPkiEnvelopeEncoder(ca,
                cipherAlgorithm);
        PkiMessageEncoder encoder = new PkiMessageEncoder(
                clientPair.getPrivate(), client, envEncoder, "SHA1withRSA",
                asnEncoding);

        PkcsPkiEnvelopeDecoder envDecoder = new PkcsPkiEnvelopeDecoder(ca,
                caPair.getPrivate());
        PkiMessageDecoder decoder = new PkiMessageDecoder(client, envDecoder);

        PkiMessage<?> actual = decoder.decode(encoder.encode(message));

        return actual;
    	
    }
}
