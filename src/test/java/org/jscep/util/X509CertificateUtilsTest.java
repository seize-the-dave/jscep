package org.jscep.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.BeforeClass;
import org.junit.Test;


/*
 * Provides basic unit tests for the X509CertificateUtils class 
 */

public class X509CertificateUtilsTest {

	@BeforeClass
    public static void beforeClass() {
		 Security.addProvider(new BouncyCastleProvider());
    }
	
	
	/**
	 * Standard regression test
	 */
	@Test(expected = NullPointerException.class)
	public void testNullList() {
		X509CertificateUtils.orderCertificateChainRootLast(null);
	}

	/**
	 * Standard regression test
	 */
	@Test
	public void testEmptyList() {
		List<? extends Certificate> result = X509CertificateUtils.orderCertificateChainRootLast(Collections.emptyList());
		assertTrue("List returned empty as expected.", result.isEmpty());
	}

	/**
	 * Verifies that a simple root certificate is handled as expected
	 */
	@Test
	public void testOnRootCertificate() throws NoSuchAlgorithmException, CertificateParsingException, OperatorCreationException, CertIOException {
		// Generate a self signed root certificate
		final KeyPair rootKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
		final String rootDn = "CN=root";
	 	X509Certificate rootCertificate = SimpleCertGenerator.forTESTCaCert()
			.setSubjectDn(rootDn)
			.setIssuerDn(rootDn)
			.setSignatureAlgorithm("SHA256WithRSA")
			.setSelfSignKeyPair(rootKeyPair)
			.generateCertificate();	 	
	 	List<? extends Certificate> result = X509CertificateUtils.orderCertificateChainRootLast(Arrays.asList(rootCertificate));
	 	assertEquals("orderCertificateChainRootLast failed on ordering a single certificate", 1, result.size());
	}
	
	/*
	 * Create a chain in a random order and verify that it gets sorted. 
	 */
	@Test
	public void testReorderCertificateChain() throws NoSuchAlgorithmException, CertificateParsingException, OperatorCreationException, CertIOException {
		// Generate a self signed root certificate
		final KeyPair rootKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
		final String rootDn = "CN=root";
	 	X509Certificate rootCertificate = SimpleCertGenerator.forTESTCaCert()
			.setSubjectDn(rootDn)
			.setIssuerDn(rootDn)
			.setSignatureAlgorithm("SHA256WithRSA")
			.setSelfSignKeyPair(rootKeyPair).generateCertificate();	 
	 	// Generate an issuing CA certificate 
		final KeyPair issuingKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
		final String issuingDn = "CN=issuer";
	 	X509Certificate issuingCertificate = SimpleCertGenerator.forTESTCaCert()
			.setSubjectDn(issuingDn)
			.setIssuerDn(rootDn)
			.setSignatureAlgorithm("SHA256WithRSA")
			.setIssuerPubKey(rootKeyPair.getPublic())
			.setIssuerPrivKey(rootKeyPair.getPrivate())
			.setEntityPubKey(issuingKeyPair.getPublic())
			.generateCertificate();	 
	 	//Create a leaf certificate 
	 	final KeyPair leafKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
	 	final String leafDn = "CN=leaf";
	 	X509Certificate leafCertificate = SimpleCertGenerator.forTESTLeafCert()
				.setSubjectDn(leafDn)
				.setIssuerDn(issuingDn)
				.setSignatureAlgorithm("SHA256WithRSA")
				.setIssuerPubKey(issuingKeyPair.getPublic())
				.setIssuerPrivKey(issuingKeyPair.getPrivate())
				.setEntityPubKey(leafKeyPair.getPublic())
				.generateCertificate();	 
	 	
	 	List<? extends Certificate> result = X509CertificateUtils.orderCertificateChainRootLast(Arrays.asList(issuingCertificate, rootCertificate, leafCertificate));
		assertTrue("Chain was not ordered in the correct order (root last)", result.get(0).equals(leafCertificate)
				&& result.get(1).equals(issuingCertificate) && result.get(2).equals(rootCertificate));
	}
	
	/*
	 * Create a chain in a random order and verify that it gets sorted. 
	 */
	@Test
	public void testReorderCertificateChainWithoutRoot() throws NoSuchAlgorithmException, CertificateParsingException, OperatorCreationException, CertIOException {
		// Generate a self signed root certificate
		final KeyPair rootKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
		final String rootDn = "CN=root";
	 	
	 	// Generate an tier 1 issuing CA certificate 
		final KeyPair t1KeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
		final String t1Dn = "CN=issuerT1";
	 	X509Certificate t1Certificate = SimpleCertGenerator.forTESTCaCert()
			.setSubjectDn(t1Dn)
			.setIssuerDn(rootDn)
			.setSignatureAlgorithm("SHA256WithRSA")
			.setIssuerPubKey(rootKeyPair.getPublic())
			.setIssuerPrivKey(rootKeyPair.getPrivate())
			.setEntityPubKey(t1KeyPair.getPublic())
			.generateCertificate();	 
	 	
	 	// Generate an tier 2 issuing CA certificate 
 		final KeyPair t2KeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
 		final String t2Dn = "CN=issuerT2";
 	 	X509Certificate t2Certificate = SimpleCertGenerator.forTESTCaCert()
 			.setSubjectDn(t2Dn)
 			.setIssuerDn(t1Dn)
 			.setSignatureAlgorithm("SHA256WithRSA")
 			.setIssuerPubKey(t1KeyPair.getPublic())
 			.setIssuerPrivKey(t1KeyPair.getPrivate())
 			.setEntityPubKey(t2KeyPair.getPublic())
 			.generateCertificate();	 
	 	
	 	
	 	//Create a leaf certificate 
	 	final KeyPair leafKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
	 	final String leafDn = "CN=leaf";
	 	X509Certificate leafCertificate = SimpleCertGenerator.forTESTLeafCert()
				.setSubjectDn(leafDn)
				.setIssuerDn(t2Dn)
				.setSignatureAlgorithm("SHA256WithRSA")
				.setIssuerPubKey(t2KeyPair.getPublic())
				.setIssuerPrivKey(t2KeyPair.getPrivate())
				.setEntityPubKey(leafKeyPair.getPublic())
				.generateCertificate();	 
	 	
	 	List<? extends Certificate> result = X509CertificateUtils.orderCertificateChainRootLast(Arrays.asList(t1Certificate, leafCertificate, t2Certificate));
		assertTrue("Chain was not ordered in the correct order (t2 last)", result.get(0).equals(leafCertificate)
				&& result.get(1).equals(t2Certificate) && result.get(2).equals(t1Certificate));
	}

}
