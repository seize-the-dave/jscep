package org.jscep.util;

import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

/**
 * Utility class for performing operations on X.509 certificates
 */

public final class X509CertificateUtils {

	private X509CertificateUtils() {

	}
	
	/**
	 * This method takes an unorderd list of certificates and sets them in order, root last. 
	 * 
	 * @param unorderedList a list of certificates
	 * @return the list, but ordered by root last
	 */
	public static List<? extends Certificate> orderCertificateChainRootLast(final Collection<? extends Certificate> unorderedList) {
		Objects.requireNonNull(unorderedList);

		if (unorderedList.size() <= 1 ) {
			return new ArrayList<>(unorderedList);
		}	

		List<X509Certificate> result = new ArrayList<>();
		// Generate a map of certificates, based on subject. Note the root cert may not
		// be present in the chain.
		Map<X500Name, X509Certificate> certificateMap = new HashMap<>();		
		Set<X500Name> issuers = new HashSet<>();
		try {
			for (Certificate certificate : unorderedList) {
				JcaX509CertificateHolder holder = new JcaX509CertificateHolder((X509Certificate) certificate);			
				certificateMap.put(holder.getSubject(), (X509Certificate) certificate);
				issuers.add(holder.getIssuer());
			}
			//Find the lowest level cert
			Certificate nextCertificate = null;
			for (Certificate certificate : unorderedList) {
				if(!issuers.contains(new JcaX509CertificateHolder((X509Certificate) certificate).getSubject())) {
					nextCertificate = certificate;
					break;
				}
			}
			if(nextCertificate == null) {
				throw new IllegalStateException("List consisted only of self signed certificates, cannot continue.");
			}
			
			// Starting at the lowest level certificate, build the chain, root last.
			while (nextCertificate != null) {
				result.add((X509Certificate) nextCertificate);
				if(isRootCertificate((X509Certificate) nextCertificate)) {
					break;
				} else {
					nextCertificate = certificateMap.get(new JcaX509CertificateHolder((X509Certificate) nextCertificate).getIssuer());
				}

			}
		} catch (CertificateEncodingException e) {
			throw new IllegalStateException("Certificate could not be parsed as an X509Certificate", e);
		}
		return result;

	}

	private static boolean isRootCertificate(final X509Certificate certificate) throws CertificateEncodingException {
		JcaX509CertificateHolder holder = new JcaX509CertificateHolder(certificate);
		return holder.getSubject().equals(holder.getIssuer());
	}
}
