package org.jscep.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Date;
import java.util.List;
import java.util.Objects;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.BufferingContentSigner;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class is a simplified version of the corresponding class in EJBCA's test code, and provides a quick and dirty way of producing test certificates. 
 * 
 * Do NOT use this code in production. 
 */
public final class SimpleCertGenerator {
	
	private static final Logger log = LoggerFactory
			.getLogger(SimpleCertGenerator.class);

    private static final String DEFAULT_TESTCERT_DN = "CN=Test,O=Test,C=SE";
    private static final int DEFAULT_TESTCERT_VALIDITY = 365*40;

    private String subjectDn;
    private String issuerDn;
    private boolean issuerDnSet = false;
    private Date firstDate;
    private Date lastDate;
    private int validityDays = 1; // lastDate, if set, overrides this
    private String policyId = null;
    private PublicKey issuerPubKey;
    private PrivateKey issuerPrivKey;
    private PublicKey entityPubKey;
    private String sigAlg;
    private boolean isCa = false;
    private int keyUsage = -1; // default is set later
    private Date privateKeyNotBefore;
    private Date privateKeyNotAfter;
    private final String provider; // default is set later
    private boolean ldapOrder;
    private List<Extension> additionalExtensions;

    /**
     * Private to avoid parameter confusion. Use  {@link #forLeafCert} instead,
     * (or {@link #forTESTCaCert} / {@link #forTESTLeafCert} in tests).
     */
    private SimpleCertGenerator(final boolean isCa, final String subjectDn, final String issuerDn, final int validityDays) {
        this.isCa = isCa;
        this.subjectDn = subjectDn;
        this.issuerDn = issuerDn;
        this.issuerDnSet = true;
        this.validityDays = validityDays;
        this.provider = BouncyCastleProvider.PROVIDER_NAME;
    }

    /** Creates a CA TEST certificate with 40 year validity and Subject DN "CN=Test,O=Test,C=SE" */
    public static SimpleCertGenerator forTESTCaCert() {
        return new SimpleCertGenerator(true, DEFAULT_TESTCERT_DN, DEFAULT_TESTCERT_DN, DEFAULT_TESTCERT_VALIDITY);
    }

    /** Creates a TEST leaf certificate with 40 year validity and Subject DN "CN=Test,O=Test,C=SE" */
    public static SimpleCertGenerator forTESTLeafCert() {
        return new SimpleCertGenerator(false, DEFAULT_TESTCERT_DN, DEFAULT_TESTCERT_DN, DEFAULT_TESTCERT_VALIDITY);
    }

    public String getSubjectDn() {
        return subjectDn;
    }
    /** Sets the Subject DN */
    public SimpleCertGenerator setSubjectDn(final String subjectDn) {
        this.subjectDn = subjectDn;
        return this;
    }
    /** Sets the Issuer DN. The default is to use the same value as Subject DN. */
    public String getIssuerDn() {
        return issuerDn;
    }
    public SimpleCertGenerator setIssuerDn(final String issuerDn) {
        this.issuerDn = issuerDn;
        issuerDnSet = true;
        return this;
    }
    public Date getFirstDate() {
        return firstDate;
    }
    /** Sets the notBefore date */
    public SimpleCertGenerator setFirstDate(final Date firstDate) {
        this.firstDate = firstDate;
        return this;
    }
    public Date getLastDate() {
        return lastDate;
    }
    /**
     * Sets the expiration/notAfter date.
     * The default is to use the value from setValidityDays, or 1 day if not set (or 40 years for test certificates).
     */
    public SimpleCertGenerator setLastDate(final Date lastDate) {
        this.lastDate = lastDate;
        return this;
    }
    public int getValidityDays() {
        return validityDays;
    }
    /**
     * Sets the validity in days. The default is 1 day (or 40 years for test certificates).
     * Note that setLastDate overrides this.
     */
    public SimpleCertGenerator setValidityDays(final int validityDays) {
        this.validityDays = validityDays;
        return this;
    }
    public String getPolicyId() {
        return policyId;
    }
    /** Policy string (e.g. '2.5.29.32.0') */
    public SimpleCertGenerator setPolicyId(final String policyId) {
        this.policyId = policyId;
        return this;
    }

    public PublicKey getIssuerPubKey() {
        return issuerPubKey;
    }

    public PrivateKey getIssuerPrivKey() {
        return issuerPrivKey;
    }
    /** Sets the end issuer's private key. Use {@link #setSelfSignKeyPair} instead for self-signed certs. */
    public SimpleCertGenerator setIssuerPrivKey(final PrivateKey issuerPrivKey) {
        this.issuerPrivKey = issuerPrivKey;
        return this;
    }
    public SimpleCertGenerator setIssuerPubKey(final PublicKey issuerPubKey) {
        this.issuerPubKey = issuerPubKey;
        return this;
    }

    public PublicKey getEntityPubKey() {
        return entityPubKey;
    }
    /** Sets the end entity's public key. Use {@link #setSelfSignKeyPair} instead for self-signed certs. */
    public SimpleCertGenerator setEntityPubKey(final PublicKey entityPubKey) {
        this.entityPubKey = entityPubKey;
        return this;
    }

    /** Uses the same keypair for both public and private key, i.e. self-signing. */
    public SimpleCertGenerator setSelfSignKeyPair(final KeyPair keyPair) {
        setEntityPubKey(keyPair.getPublic());
        setIssuerPrivKey(keyPair.getPrivate());
        return this;
    }

    public String getSignatureAlgorithm() {
        return sigAlg;
    }
    /** Sets the signature algorithm. You can use one of the constants AlgorithmConstants.SIGALG_XXX */
    public SimpleCertGenerator setSignatureAlgorithm(final String sigAlg) {
        this.sigAlg = sigAlg;
        return this;
    }


    public boolean isCa() {
        return isCa;
    }
    public SimpleCertGenerator setCa(final boolean isCA) {
        this.isCa = isCA;
        return this;
    }
    public int getKeyUsage() {
        return keyUsage;
    }
    /**
     * Sets the key usage. Use the constants in X509KeyUsage. Set to NO_KEY_USAGE to exclude from cert.
     *
     * The default is keyCertSign + cRLSign for CA certs, and absent/excluded for non-CA certs.
     */
    public SimpleCertGenerator setKeyUsage(final int keyUsage) {
        this.keyUsage = keyUsage;
        return this;
    }
    public Date getPrivateKeyNotBefore() {
        return privateKeyNotBefore;
    }
    public SimpleCertGenerator setPrivateKeyNotBefore(final Date privateKeyNotBefore) {
        this.privateKeyNotBefore = privateKeyNotBefore;
        return this;
    }
    public Date getPrivateKeyNotAfter() {
        return privateKeyNotAfter;
    }
    public SimpleCertGenerator setPrivateKeyNotAfter(final Date privateKeyNotAfter) {
        this.privateKeyNotAfter = privateKeyNotAfter;
        return this;
    }

    public boolean isLdapOrder() {
        return ldapOrder;
    }
    public SimpleCertGenerator setLdapOrder(final boolean ldapOrder) {
        this.ldapOrder = ldapOrder;
        return this;
    }
    public List<Extension> getAdditionalExtensions() {
        return additionalExtensions;
    }
    public SimpleCertGenerator setAdditionalExtensions(final List<Extension> additionalExtensions) {
        this.additionalExtensions = additionalExtensions;
        return this;
    }


    private void setDefaults() {
        Objects.requireNonNull(issuerPrivKey, "issuerPrivKey must be set");
        Objects.requireNonNull(entityPubKey, "entityPubKey must be set");
        // In theory, AlgorithmTools.getSignatureAlgorithms(entityPubKey).get(0) could be used for auto-detection,
        // but that gives SHA1 for RSA keys, which is not acceptable.
        Objects.requireNonNull(sigAlg, "Signature algorithm must be set");
        if (!issuerDnSet) {
            // When issuer DN is not explicitly set, assume we're creating a self-signed cert
            issuerDn = subjectDn;
        }
        if (firstDate == null) {
            firstDate = new Date();
            // Set back startdate ten minutes to avoid some problems with wrongly set clocks.
            firstDate.setTime(firstDate.getTime() - (10 * 60 * 1000));
        }
        if (lastDate == null) {
            lastDate = new Date();
            // validity in days = validity*24*60*60*1000 milliseconds
            lastDate.setTime(lastDate.getTime() + (Long.valueOf(validityDays) * (24l * 60l * 60l * 1000l)));
        }
        if (keyUsage == -1) {
            if (isCa) {
                keyUsage = X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign;
            } else {
                keyUsage = 0;
            }
        }
    }

    private PublicKey decoratePublicKey(PublicKey pubKeyToDecorate) {
        PublicKey publicKey = null;
        if (pubKeyToDecorate instanceof RSAPublicKey) {
            RSAPublicKey rsapk = (RSAPublicKey) pubKeyToDecorate;
            final RSAPublicKeySpec rSAPublicKeySpec = new RSAPublicKeySpec(rsapk.getModulus(), rsapk.getPublicExponent());
            try {
                publicKey = KeyFactory.getInstance("RSA").generatePublic(rSAPublicKeySpec);
            } catch (InvalidKeySpecException e) {
                log.error("Error creating RSAPublicKey from spec: ", e);
                publicKey = pubKeyToDecorate;
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException("RSA was not a known algorithm", e);
            }
        } else if (pubKeyToDecorate instanceof ECPublicKey) {
            ECPublicKey ecpk = (ECPublicKey) pubKeyToDecorate;
            try {
                final ECPublicKeySpec ecspec = new ECPublicKeySpec(ecpk.getW(), ecpk.getParams());            
				try {
					publicKey = KeyFactory.getInstance("EC").generatePublic(ecspec);
				} catch (NoSuchAlgorithmException e) {
					throw new IllegalStateException("EC was not a known algorithm", e);
				}                
            } catch (InvalidKeySpecException e) {
                log.error("Error creating ECPublicKey from spec: ", e);
                publicKey = pubKeyToDecorate;
            } 
        } else {
            log.debug("Not converting key of class. " + pubKeyToDecorate.getClass().getName());
            publicKey = pubKeyToDecorate;
        }
        return publicKey;
    }

    public X509Certificate generateCertificate() throws CertificateParsingException, OperatorCreationException, CertIOException {
        setDefaults();

        // Transform the PublicKey to be sure we have it in a format that the X509 certificate generator handles, it might be
        // a CVC public key that is passed as parameter
        PublicKey publicKey = decoratePublicKey(entityPubKey);
        PublicKey issuerPublicKey = publicKey;
        if (this.issuerPubKey!=null) {
            issuerPublicKey = decoratePublicKey(this.issuerPubKey);
        }

        // Serial number is random bits
        final byte[] serno = new byte[16];
        final SecureRandom random = new SecureRandom();
        random.nextBytes(serno);

        final SubjectPublicKeyInfo pkinfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        final X509v3CertificateBuilder certbuilder = new X509v3CertificateBuilder(new X500Name(issuerDn), new BigInteger(serno).abs(),
                firstDate, lastDate, new X500Name(subjectDn), pkinfo);

        addExtensions(publicKey, issuerPublicKey, certbuilder);
        final X509CertificateHolder certHolder = signCert(certbuilder, issuerPrivKey, sigAlg, provider);
        final X509Certificate selfcert;
        try {
            selfcert = parseCertificate(certHolder.getEncoded());
        } catch (IOException e) {
            throw new IllegalStateException("Unexpected IOException was caught.", e);
        }

        return selfcert;
    }
    
    private X509Certificate parseCertificate( byte[] cert) throws CertificateParsingException {
        CertificateFactory cf;
		try {
			cf = CertificateFactory.getInstance("X.509", provider);
		} catch (CertificateException e) {
			throw new CertificateParsingException(e);
		} catch (NoSuchProviderException e) {
			throw new IllegalStateException("Bouncycastle was not found as a provider.", e);
		}
        X509Certificate result;
        try {
           result = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(cert));      
        } catch (CertificateException e) {
            throw new CertificateParsingException("Could not parse byte array as X509Certificate." + e.getCause().getMessage(), e);
        }
        if(result != null) {
            return result;
        } else {
            throw new CertificateParsingException("Could not parse byte array as X509Certificate.");
        }
    }
    
   
    
    
    
    private void addExtensions(final PublicKey publicKey, final PublicKey issuerPublicKey, final X509v3CertificateBuilder certbuilder) throws CertIOException {
        // Basic constranits is always critical and MUST be present at-least in CA-certificates.
        final BasicConstraints bc = new BasicConstraints(isCa);
        certbuilder.addExtension(Extension.basicConstraints, true, bc);

        // Put critical KeyUsage in CA-certificates
        if (isCa || keyUsage != 0) {
            final X509KeyUsage ku = new X509KeyUsage(keyUsage);
            certbuilder.addExtension(Extension.keyUsage, true, ku);
        }

        if ((privateKeyNotBefore != null) || (privateKeyNotAfter != null)) {
            final ASN1EncodableVector v = new ASN1EncodableVector();
            if (privateKeyNotBefore != null) {
                v.add(new DERTaggedObject(false, 0, new DERGeneralizedTime(privateKeyNotBefore)));
            }
            if (privateKeyNotAfter != null) {
                v.add(new DERTaggedObject(false, 1, new DERGeneralizedTime(privateKeyNotAfter)));
            }
            certbuilder.addExtension(Extension.privateKeyUsagePeriod, false, new DERSequence(v));
        }

        // Subject and Authority key identifier is always non-critical and MUST be present for certificates to verify in Firefox.
        try {
            if (isCa) {
                final JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils(SHA1DigestCalculator.buildSha1Instance());
                final SubjectKeyIdentifier ski = extensionUtils.createSubjectKeyIdentifier(publicKey);
                final AuthorityKeyIdentifier aki = extensionUtils.createAuthorityKeyIdentifier(issuerPublicKey);
                certbuilder.addExtension(Extension.subjectKeyIdentifier, false, ski);
                certbuilder.addExtension(Extension.authorityKeyIdentifier, false, aki);
            }
        } catch (IOException e) { // do nothing
        }

        // CertificatePolicies extension if supplied policy ID, always non-critical
        if (policyId != null) {
            final PolicyInformation pi = new PolicyInformation(new ASN1ObjectIdentifier(policyId));
            final DERSequence seq = new DERSequence(pi);
            certbuilder.addExtension(Extension.certificatePolicies, false, seq);
        }
        // Add any additional extensions
        if (additionalExtensions != null) {
            for (final Extension extension : additionalExtensions) {
                certbuilder.addExtension(extension.getExtnId(), extension.isCritical(), extension.getParsedValue());
            }
        }
    }

    private static X509CertificateHolder signCert(final X509v3CertificateBuilder certbuilder, final PrivateKey issuerPrivKey, 
            final String sigAlg,  final String provider) throws OperatorCreationException {

        final ContentSigner signer = new BufferingContentSigner(new JcaContentSignerBuilder(sigAlg).setProvider(provider).build(issuerPrivKey), 20480);
        return certbuilder.build(signer);
    }
    
    private static class SHA1DigestCalculator implements DigestCalculator {
        private ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        private MessageDigest digest;

        public SHA1DigestCalculator(MessageDigest digest) {
            this.digest = digest;
        }

        @Override
        public AlgorithmIdentifier getAlgorithmIdentifier() {
            return RespID.HASH_SHA1;
        }

        @Override
        public OutputStream getOutputStream() {
            return bOut;
        }

        @Override
        public byte[] getDigest() {
            byte[] bytes = digest.digest(bOut.toByteArray());
            bOut.reset();
            return bytes;
        }
        
        public static SHA1DigestCalculator buildSha1Instance() {
            try {
                return new SHA1DigestCalculator(MessageDigest.getInstance("SHA1"));
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException(e);
            }
        }
    }
}
