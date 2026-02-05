jscep [![Build Status](https://github.com/jscep/jscep/workflows/Build/badge.svg "GitHub Actions")](https://github.com/jscep/jscep/actions?query=workflow%3ABuild) [![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.google.code.jscep/jscep/badge.svg)](https://maven-badges.herokuapp.com/maven-central/com.google.code.jscep/jscep)
=====

jscep is a Java implementation of the SCEP protocol.

## Getting Support

If you have a question about the jscep library, please send an email to davegrant674@gmail.com.

## Constructing a Client


In order to construct a client, we need two objects:
  
- a URL
- a Callback Handler
  
## Determining the URL

  The URL should be obtained from your system administrator.  In the case of Microsoft NDES, the URL will look like so:
  
```java
URL url = new URL("http://[host]/certsrv/mscep_admin/mscep.dll");
```
  
In the case of EJBCA, it will look like so:
  
```java
URL url = new URL("http://[host]/ejbca/publicweb/apply/scep/pkiclient.exe");
```

### Using a HTTP Proxy

jscep doesn't directly support using a proxy to access your SCEP server, as it doesn't really make sense for SCEP.  However, if you need to use a proxy, you can use the mechanism provided by 
[ProxySelector](http://docs.oracle.com/javase/6/docs/api/java/net/ProxySelector.html), like so:
  
```java
ProxySelector.setDefault(new ProxySelector() {
    @Override
    public List<Proxy> select(URI uri) {
      Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("squid", 3128);
    	return Collections.singletonList(proxy);
    }
    
    @Override
    public void connectFailed(URI uri, SocketAddress sa, IOException ioe) {
    	// Do nothing
    } 
});
```
  
### Using HTTPS

jscep uses [HttpURLConnection](http://docs.oracle.com/javase/6/docs/api/java/net/HttpURLConnection.html) under the hood,
and offers full support for HTTPS-enabled SCEP servers - although SCEP doesn't require a HTTPS connection.
   
If your SCEP server requires the use of SSL to establish a connection, you may wish to configure 
[HttpsURLConnection](http://docs.oracle.com/javase/6/docs/api/javax/net/ssl/HttpsURLConnection.html) by using the static 
`setDefaultHostnameVerifier` and `setDefaultSSLSocketFactory` methods. You'll only need to specify a `HostnameVerifier` 
if your SSL server provides a certificate that doesn't match the hostname in the SCEP URL.
  
By default, `HttpsURLConnection` will use the `SSLSocketFactory` as specified by JSSE, so there should be no need to configure it directly.  However, if you do want to customise the socket factory, you can do this by customising the transport (see below).

For more information, read the [JSSE Reference Guide](http://docs.oracle.com/javase/6/docs/technotes/guides/security/jsse/JSSERefGuide.html),
particularly the section on [customization](http://docs.oracle.com/javase/6/docs/technotes/guides/security/jsse/JSSERefGuide.html#Customization).

### Customising the Transport

If you want to provide your own transport implementation (e.g. using something other than HttpURLConnection) take a look at the [TransportFactory](https://github.com/jscep/jscep/blob/master/src/main/java/org/jscep/transport/TransportFactory.java) interface.  Once instantiated, you can inject the custom `TransportFactory` using `Client.setTransportFactory()`.

If you're looking to customise the default `SSLSocketFactory` used by [UrlConnectionTransportFactory](https://github.com/jscep/jscep/blob/master/src/main/java/org/jscep/transport/UrlConnectionTransportFactory.java), you can do so without creating your own custom `TransportFactory`. Instead, instantiate `UrlConnectionTransportFactory` yourself, and pass in your customised `SSLSocketFactory`, like so:

```java
SSLSocketFactory factory = new CustomisedSSLSocketFactory();

Client client = new Client(url, handler);
client.setTransportFactory(new UrlConnectionTransportFactory(factory));
```

Ernst-Georg Schmid has created a transport which uses HTTP Basic authentication.  You can find his repo at [ergo70/jscep-basic-auth](https://github.com/ergo70/jscep-basic-auth).

### ASN.1 encoding

Some SCEP servers require definite-length BER encoding and reject messages with indefinite-length encoding. By default, jscep uses indefinite-length encoding. To use definite-length encoding, set the `AsnEncoding` option on the client:

```java
Client client = new Client(url, handler);
client.setAsnEncoding(AsnEncoding.DL);
```

This encoding is applied to both the inner `CMSEnvelopedData` and the outer `CMSSignedData` structures.

## Creating a Callback Handler

The callback handler is used to verify the CA certificate being sent by the SCEP server is the certificate you expect.  With jscep, you can choose to use either the default callback mechanism with a choice of certificate verifiers, or to provide your own callback handler.
  
### Default Callback Mechanism

The default callback mechanism provides a `DefaultCallbackHandler` which delegates verification to a `CertificateVerifier` implementation.  jscep supports several strategies for verifying a certificate, including pre-provisioned certificates or digests, and an interactive console verifier. The following example shows the steps necessary to configure the console verifier:
  
```java
  CertificateVerifier verifier = new ConsoleCertificateVerifier();
  CallbackHandler handler = new DefaultCallbackHandler(verifier);
```

By default, jscep will request verification before each operation.  If you are performing a number of operations against the same SCEP server, you may wish to cache the users response by decorating the certificate verifier, like so:
  
```java
  CertificateVerifier consoleVerifier = new ConsoleCertificateVerifier();
  CertificateVerifier verifier = new CachingCertificateVerifier(consoleVerifier);
  CallbackHandler handler = new DefaultCallbackHandler(verifier);
```

### Providing Your Own Callback Handler

If you wish to use your own `CallbackHandler`, you must handle the `CertificateVerificationCallback`. 

# Creating the Client

To create the client, just combine the two parameters:

```java
Client client = new Client(url, handler);
```

The client is thread-safe, so you can use to enrol multiple entities in parallel if you're using the same CA.

## Profiles

If your SCEP server supports multiple CAs, your CA administrator must provide a string to identify the issuer to use. Each of the operations supported by jscep accepts an optional profile parameter in the form of a `String`.
  
Because the jscep client is thread-safe, your application can invoke operations against multiple CA profiles _without_ having to construct a new SCEP client.
  
*Note:* Microsoft NDES _always_ requires a profile.

# Initialising the Requester

In each SCEP message exchange, there are two parties: the requester -- who is enrolling a particular entity into a PKI -- and a SCEP server, which represents the issuing authority, or CA.

For most operations, the SCEP server requires that the requester sign and encrypt its requests.  In turn, the server will sign and encrypt its responses.  In order for this to occur, both parties must have a certificate and key pair.
  
If the requester has been issued a certificate by the CA, the requester should use that certificate and its associated key pair.  Likewise, if the requester has been issued a certificate by a different CA which is trusted by the current CA, then the requester should use _that_ certificate and key pair.  Otherwise -- and this is for the majority of cases -- the requester should generate a self-signed certificate.
  
## Generating a Key Pair

Before we can generate a certificate, we must first generate a key pair.  The SCEP specification only supports RSA, so that is what we will use.  The JCA requires Java implementations to support 1024 and 2048-bit keys.

```java
KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
keyPairGenerator.initialize(1024);
KeyPair requesterKeyPair = keyPairGenerator.genKeyPair();
```

## Generating a Self-Signed Certificate

Once you have your key pair, the next step is to generate an X509 Certificate.  The JCA doesn't provide a mechanism for building certificates programmatically.  However, you _can_ use Bouncy Castle to do it, using either the [JcaX509v1CertificateBuilder](http://www.bouncycastle.org/docs/pkixdocs1.5on/org/bouncycastle/cert/jcajce/JcaX509v1CertificateBuilder.html) or the [JcaX509v3CertificateBuilder](http://www.bouncycastle.org/docs/pkixdocs1.5on/org/bouncycastle/cert/jcajce/JcaX509v3CertificateBuilder.html) class.
  
The following example uses `JcaX509v3CertificateBuilder` due to its support for X509 extensions.  Bouncy Castle provides classes and interfaces to  simplify the usage of extensions through the [org.bouncycastle.asn1.x509](http://www.bouncycastle.org/docs/docs1.5on/org/bouncycastle/asn1/x509/package-summary.html) package.
  
If you don't require extensions, you can use `JcaX509v1CertificateBuilder`, which takes the same arguments as `JcaX509v3CertificateBuilder` in its JCA-compatible constructor.  In either case, you will need to provide a `ContentSigner`, which can bebuilt using [JcaContentSignerBuilder](http://www.bouncycastle.org/docs/pkixdocs1.5on/org/bouncycastle/operator/jcajce/JcaContentSignerBuilder.html).

SCEP supports the following signature algorithms:
  
 - `MD5withRSA`
 - `SHA1withRSA`
 - `SHA256withRSA`
 - `SHA512withRSA`
  
You can find out the strongest signature algorithm supported by your SCEP server by using the following snippet.
  
```java
Capabilities caps = client.getCaCapabilities();
String sigAlg = caps.getStrongestSignatureAlgorithm();
```

*Note*: if you're using a self-signed certificate, your certificate subject X500 name _must_ be the same as the subject in your certificate-signing request.  
 
```java
// Mandatory
X500Principal requesterIssuer = new X500Principal("CN=jscep.org, L=Cardiff, ST=Wales, C=UK");
BigInteger serial = BigInteger.ONE;
Calendar calendar = Calendar.getInstance();
calendar.add(Calendar.DATE, -1); // yesterday
Date notBefore = calendar.getTime();
calendar.add(Calendar.DATE, +2); // tomorrow
Date notAfter = calendar.getTime();
X500Principal requesterSubject = new X500Principal("CN=jscep.org, L=Cardiff, ST=Wales, C=UK"); // doesn't need to be the same as issuer
PublicKey requesterPubKey = requesterKeyPair.getPublic(); // from generated key pair
JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(requesterIssuer, serial, notBefore, notAfter, requesterSubject, requesterPubKey);

// Optional extensions
certBuilder.addExtension(X509Extension.keyUsage, false, new KeyUsage(KeyUsage.digitalSignature));

// Signing
PrivateKey requesterPrivKey = requesterKeyPair.getPrivate(); // from generated key pair
JcaContentSignerBuilder certSignerBuilder = new JcaContentSignerBuilder(sigAlg); // from above
ContentSigner certSigner = signerBuilder.build(requesterPrivKey);

X509CertificateHolder certHolder = certBuilder.build(certSigner);
```

You can extract a JCA-compatible certificate by using the [JcaX509CertificateConverter](http://www.bouncycastle.org/docs/pkixdocs1.5on/org/bouncycastle/cert/jcajce/JcaX509CertificateConverter.html):

```java
JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
X509Certificate requesterCert = converter.getCertificate(certHolder);
```

Congratulations! You now have everything you need to invoke operations against your SCEP server.

# Certificate Enrollment

Certificate enrollment is the primary use-case for using the SCEP protocol.

## Enrolling a Certificate

When enrolling an entity into a PKI, you should generate a new key pair to represent the entity, as shown in the following snippet.  There is no reason not to reuse the `KeyPairGenerator` from the earlier steps, but we'll create another here for simplicity.
  
```java
KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
keyPairGenerator.initialize(1024);
KeyPair entityKeyPair = keyPairGenerator.genKeyPair();
```

We'll name this key pair `entityKeyPair` to distinguish it from the key pair used to represent the SCEP client, which is named `requesterKeyPair`.  After the key pair has been created, we need to start creating the signing request to send to the CA.  Since the JCA does not support the creation of CSRs, we'll use Bouncy Castle again:
  
```java
X500Principal entitySubject = requesterSubject; // use the same subject as the self-signed certificate
PublicKey entityPubKey = entityKeyPair.getPublic();
PKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(entitySubject, entityPubKey); 
```

We can now use the `PKCS10CertificationRequestBuilder` to add attributes.  Depending on your SCEP server, you may need to provide additional extensions, but in *most* cases, you'll add a PKCS#9 `challengePassword`:

```java
DERPrintableString password = new DERPrintableString("password");
csrBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_challengePassword, password);
```

If you're renewing a certificate, you should still send an empty password, as per the following snippet, but the SCEP server must validate the request against the requester certificate, `requesterCert`.
  
```java
DERPrintableString password = new DERPrintableString("");
csrBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_challengePassword, password);
```

### Extensions

If you wish to add extensions to your CSR, add an extensionRequest OID.  BC provides an `ExtensionsGenerator` to simplify common use cases:
  
```java
ExtensionsGenerator extGen = new ExtensionsGenerator();
extGen.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_eapOverLAN));
csrBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());
```

In some cases, BC won't provide a specific object, so you'll have to build it yourself:
  
```java
ASN1EncodableVector otherName = new ASN1EncodableVector(); 
otherName.add(new DERObjectIdentifier("1.3.6.1.4.1.311.20.2.3")); 
otherName.add(new DERTaggedObject(true, 0, new DERUTF8String( "devuser@dvam.local"))); 
ASN1Object genName = new DERTaggedObject(false, 0, new DERSequence(otherName)); 

ASN1EncodableVector genNames = new ASN1EncodableVector();
genNames.add(genName);

ExtensionsGenerator extGen = new ExtensionsGenerator();
extGen.addExtension(Extension.subjectAlternativeName, true, new DERSequence(genNames));
```

### Signing the CSR

When you've finished adding your attributes, you must then sign your CSR with your entity's private key.

```java
PrivateKey entityPrivKey = entityKeyPair.getPrivate();
JcaContentSignerBuilder csrSignerBuilder = new JcaContentSignerBuilder("SHA1withRSA");
ContentSigner csrSigner = csrSignerBuilder.build(entityPrivKey);
PKCS10CertificationRequest csr = csrBuilder.build(csrSigner); 
```

You now have everthing you need to enrol.  The next line in your application will typically be to send the CSR to the SCEP server, and to assign the response.

```java
EnrollmentResponse res = client.enrol(requesterCert, requesterPrivKey, csr);
```

Understanding the server response is critical for knowing what to do next.

## Enrollment Response

The `EnrollmentResponse` returned by `Client.enrol()` and `Client.poll()` should be inspected by your application to determine what to do next.  `EnrollmentResponse` contains three methods which can be used to determine the state of the response:
  
 - `isSuccess()`
 - `isPending()`
 - `isFailure()`
  
If `isSuccess()` returns `true`, your application should call `getCertStore()` to retrieve the enrolled certificates.  For a lot of applications, this will be the last interaction you have with the jscep client.  
  
If `isFailure()` returns `true`, your application should call `getFailInfo()` to determine the reason for failure.  Applications should treat this as a permanent failure.  Unfortunately, the SCEP protocol doesn't provide a lot of detail for failure reasons, so it is non-trivial to make your application resilient to SCEP failure.
  
The last method, `isPending()`, is guaranteed to be `true` if the other two methods return `false`.  For pending response,  your application should call `getTransactionId()`, and use the returned `TransactionId` when invoking `Client.poll()`, as detailed below.
  
Your application may use a number of different approaches for sending a poll request to the server, and jscep does not attempt to second-guess how your application will want to approach this situation.  However, it should be noted that all of the classes used as arguments to `poll` implement `Serializable` and are immutable, so can safely be used in different threads and even in different JVMs.
  
Applications are *strongly* recommended not to pass the requester `PrivateKey` around in the clear.  The JCA provides the `KeyStore` class for securely storing keys, and can store the requester certificate and pair like so:
  
```java
KeyStore store = KeyStore.getInstance("JKS");
store.load(null, null);
store.setKeyEntry("requester", requesterPrivKey, "secret".toCharArray(), requesterCert);

ByteArrayOutputStream bOut = new ByteArrayOutputStream();
store.store(bOut, "secret".toCharArray());
```

Alternatively, applications can use a `SealedObject` to simplify serialization, but this is arguably more complicated.

## Polling for a Pending Enrollment

If your application has previously received a _pending_ response, your application should poll the SCEP server to determine the current state of the enrollment.  The `poll()` method returns the same type as the `enrol()` method, so applications should follow the same steps to determine the _current_ state of the enrollment.

```java
EnrollmentResponse res = client.poll(requesterCert, requesterPrivKey, subject, transId);
```

Since issuing a certificate may involve a lengthy manual process, your application may have to make numerous polling requests.

# Non-Enrollment Operations

## CRL Access

If you need to retrieve a CRL for a particular certificate.

```java
X509CRL crl = client.getRevocationList(cert, keyPair.getPrivate(), issuer, serial);
```

## Certificate Access

If you need to access a certificate that was previously issued, you need only pass the serial number of the certificate:

```java
CertStore store = client.getCertificate(cert, keyPair.getPrivate(), serial);
```

## CA Capabilities

The capabilities of the SCEP server are used extensively by internal jscep operations, for determining the cipher to use for key wrapping in the `pkcsPkiEnvelope` structure, and for the signature to use for signing the `pkiMessage` structure. 
  
By default, jscep will invoke this operation to determine which algorithms to use when constructing secure message objects. 

```java
Capabilities capabilities = client.getCaCapabilities();
```

- Digest Algorithms:
 - MD5
 - SHA-1
 - SHA-256
 - SHA-512
- Ciphers:
 - DES
 - Triple DES ( default )
 - AES-128
 - AES-192
 - AES-256 
- Use of HTTP POST (See: http://tools.ietf.org/html/draft-nourse-scep-23#appendix-C)

Note: AES-192 and AES-256 needs unrestricted policy JARs

## CA Key Rollover

```java
CertStore store = client.getRolloverCertificate();
```

See: http://tools.ietf.org/html/draft-nourse-scep-23#appendix-E

## RA/CA Certificate Distribution

Retrieving the CA and RA certificates from the SCEP server is an important operation.

```java
CertStore store = client.getCaCertificate();
```

# Logging

To enable logging in jscep, you need to provide an [SLF4J](http://www.slf4j.org/) binding (e.g. log4j, jcl) to your classpath, then provide a configuration for your binding.  For example, the jscep project uses log4j for logging during the build process by using the following dependencies in the `pom.xml`:

```xml
<dependency>
	<groupId>org.slf4j</groupId>
	<artifactId>slf4j-log4j12</artifactId>
	<version>1.7.1</version>
	<scope>test</scope>
</dependency>
<dependency>
	<groupId>log4j</groupId>
	<artifactId>log4j</artifactId>
	<version>1.2.17</version>
	<scope>test</scope>
</dependency>
```

and using this configration file: https://github.com/jscep/jscep/blob/master/src/test/resources/log4j.properties

# Credits

Thanks to Ryan Schipper and Danny deSousa for contributions to this manual.

# References

* [Bouncy Castle PKIX and CMS Documentation](http://www.bouncycastle.org/docs/pkixdocs1.5on/index.html)
* [Bouncy Castle Provider and Main Documentation](http://www.bouncycastle.org/docs/docs1.5on/index.html)
* [Java 6 Security](http://docs.oracle.com/javase/6/docs/technotes/guides/security/)
* [Active Directory Certificate Services and Public Key Management](http://technet.microsoft.com/en-us/library/cc753828(v=ws.10).aspx)
* [Network Device Enrollment Service (NDES) in Active Directory Certificate Services (AD CS)](http://social.technet.microsoft.com/wiki/contents/articles/9063.network-device-enrollment-service-ndes-in-active-directory-certificate-services-ad-cs.aspx)
