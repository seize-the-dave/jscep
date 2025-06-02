package org.jscep.server;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.EnumSet;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;

import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.jscep.transaction.FailInfo;
import org.jscep.transaction.OperationFailureException;
import org.jscep.transaction.TransactionId;
import org.jscep.transport.response.Capability;
import org.jscep.util.CertificationRequestUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ScepServletImpl extends ScepServlet {
    /**
     *
     */
    private static final Logger LOGGER = LoggerFactory
            .getLogger(ScepServletImpl.class);
    private static final Map<IssuerAndSerialNumber, X509Certificate> CACHE = new HashMap<IssuerAndSerialNumber, X509Certificate>();
    private static final long serialVersionUID = 1L;
    private PrivateKey priKey;
    private PublicKey pubKey;
    private X509Certificate ca;
    private X500Name name;
    private X500Name pollName;
    private BigInteger caSerial;

    public void init(ServletContext context) {
        LOGGER.debug("INIT");
    }

    @Override
    public void init() throws ServletException {
        name = new X500Name("CN=Certification Authority");
        pollName = new X500Name("CN=Poll");
        caSerial = BigInteger.TEN;
        try {

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(4096);
            KeyPair keyPair = keyPairGenerator.genKeyPair();
            priKey = keyPair.getPrivate();
            pubKey = keyPair.getPublic();
        } catch (NoSuchAlgorithmException e) {
            throw new ServletException(e);
        }
        try {
            ca = generateCertificate(pubKey, name, name, caSerial);
        } catch (Exception e) {
            throw new ServletException(e);
        }
    }

    private X509Certificate generateCertificate(PublicKey pubKey,
            X500Name subject, X500Name issuer, BigInteger serial)
            throws Exception {
        Calendar cal = GregorianCalendar.getInstance();
        cal.add(Calendar.YEAR, -1);
        Date notBefore = cal.getTime();

        cal.add(Calendar.YEAR, 2);
        Date notAfter = cal.getTime();

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer, serial, notBefore, notAfter, subject, pubKey);
        builder.addExtension(Extension.basicConstraints, true,
                new BasicConstraints(0));

        ContentSigner signer = buildContentSigner();
        X509CertificateHolder holder = builder.build(signer);
        return new JcaX509CertificateConverter().getCertificate(holder);
    }

    private ContentSigner buildContentSigner() throws Exception {
        ContentSigner signer;
        try {
            signer = new JcaContentSignerBuilder("SHA1withRSA").build(priKey);
        } catch (OperatorCreationException e) {
            throw new Exception(e);
        }
        return signer;
    }

    @Override
    protected List<X509Certificate> doEnrol(PKCS10CertificationRequest csr,
            X509Certificate sender, TransactionId transId
    ) throws OperationFailureException {
        try {
            X500Name subject = X500Name.getInstance(csr.getSubject());
            LOGGER.debug(subject.toString());
            if (subject.equals(pollName)) {
                return Collections.emptyList();
            }
            String password = CertificationRequestUtils.getChallengePassword(csr);
            if (password == null) {
                authorizeRenewal(sender);
            } else if (!password.equals("password")) {
                LOGGER.debug("Invalid password");
                throw new OperationFailureException(FailInfo.badRequest);
            }
            PublicKey pubKey = CertificationRequestUtils.getPublicKey(csr);
            X509Certificate issued = generateCertificate(pubKey, subject, name,
                    getSerial());

            LOGGER.debug("Issuing {}", issued);
            CACHE.put(
                    new IssuerAndSerialNumber(name, issued.getSerialNumber()),
                    issued);

            return Collections.singletonList(issued);
        } catch (Exception e) {
            LOGGER.debug("Error in enrollment", e);
            throw new OperationFailureException(FailInfo.badRequest);
        }
    }

    @Override
    protected List<X509Certificate> doRenew(PKCS10CertificationRequest csr,
            X509Certificate sender, TransactionId transId
    ) throws OperationFailureException {
        try {
            X500Name subject = X500Name.getInstance(csr.getSubject());
            LOGGER.debug(subject.toString());
            if (subject.equals(pollName)) {
                return Collections.emptyList();
            }
            authorizeRenewal(sender);
            PublicKey pubKey = CertificationRequestUtils.getPublicKey(csr);
            X509Certificate issued = generateCertificate(pubKey, subject, name,
                    getSerial());

            LOGGER.debug("Issuing {}", issued);
            CACHE.put(
                    new IssuerAndSerialNumber(name, issued.getSerialNumber()),
                    issued);

            return Collections.singletonList(issued);
        } catch (Exception e) {
            LOGGER.debug("Error in enrollment", e);
            throw new OperationFailureException(FailInfo.badRequest);
        }
    }

    private void authorizeRenewal(X509Certificate sender)
            throws CertificateEncodingException, OperationFailureException {
        X500Name issuer = X500Name.getInstance(sender.getIssuerX500Principal().getEncoded());
        BigInteger serial = sender.getSerialNumber();
        IssuerAndSerialNumber iasn = new IssuerAndSerialNumber(issuer, serial);
        X509Certificate certificate = CACHE.get(iasn);
        if (certificate == null || !Arrays.equals(sender.getEncoded(), certificate.getEncoded())) {
            LOGGER.debug("Unknown sender certificate on renewal");
            throw new OperationFailureException(FailInfo.badRequest);
        }
    }

    private BigInteger getSerial() {
        Random rnd = new Random();
        return BigInteger.valueOf(Math.abs(rnd.nextLong()) + 1);
    }

    @Override
    protected List<X509Certificate> doGetCaCertificate(String identifier) {
        return Collections.singletonList(ca);
    }

    @Override
    protected X509CRL doGetCrl(X500Name issuer, BigInteger serial)
            throws OperationFailureException {
        try {
            ContentSigner signer = buildContentSigner();
            X509CRLHolder crlHolder = new X509v2CRLBuilder(issuer, new Date()).build(signer);
            return new JcaX509CRLConverter().getCRL(crlHolder);
        } catch (Exception e) {
            throw new OperationFailureException(FailInfo.badRequest);
        }
    }

    @Override
    protected Set<Capability> doCapabilities(String identifier) {
        return EnumSet.of(Capability.AES, Capability.TRIPLE_DES,
                Capability.SHA_1, Capability.SHA_256, Capability.SHA_512,
                Capability.POST_PKI_OPERATION);
    }

    @Override
    protected List<X509Certificate> doGetCert(X500Name issuer, BigInteger serial)
            throws OperationFailureException {
        IssuerAndSerialNumber iasn = new IssuerAndSerialNumber(issuer, serial);

        LOGGER.debug("Searching cache for {}, {}", iasn.getName(),
                iasn.getSerialNumber());
        if (CACHE.containsKey(iasn)) {
            return Collections.singletonList(CACHE.get(iasn));
        }
        throw new OperationFailureException(FailInfo.badCertId);
    }

    @Override
    protected List<X509Certificate> doGetCertInitial(X500Name issuer,
            X500Name subject, TransactionId transId)
            throws OperationFailureException {
        if (subject.equals(pollName)) {
            return Collections.emptyList();
        }
        try {
            return Collections.singletonList(generateCertificate(pubKey,
                    subject, issuer, getSerial()));
        } catch (Exception e) {
            throw new OperationFailureException(FailInfo.badCertId);
        }
    }

    @Override
    protected List<X509Certificate> getNextCaCertificate(String identifier) {
        if (identifier == null || identifier.length() == 0) {
            return Collections.singletonList(ca);
        }
        return Collections.emptyList();
    }

    @Override
    protected PrivateKey getRecipientKey() {
        return priKey;
    }

    @Override
    protected X509Certificate getRecipient() {
        return ca;
    }

    @Override
    protected PrivateKey getSignerKey() {
        return priKey;
    }

    @Override
    protected X509Certificate getSigner() {
        return ca;
    }
    
    @Override
    protected X509Certificate[] getSignerCertificateChain() {
        return null;
    }

}
