package org.jscep.client.inspect;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.CertStore;
import java.security.cert.CertStoreParameters;
import java.security.cert.Certificate;
import java.security.cert.CollectionCertStoreParameters;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public abstract class CertStoreInspectorTest {
    @Parameterized.Parameters
    public static Collection<Object[]> setUp() throws Exception {
        InputStream keyStoreIn = CertStoreInspectorTest.class.getClassLoader()
                .getResourceAsStream("store.jks");
        KeyStore testStore = KeyStore.getInstance("JKS");
        testStore.load(keyStoreIn, "password".toCharArray());

        List<Object[]> configs = new ArrayList<Object[]>();

        configs.add(new Object[] { "ca", "ca", "ca", "ca" });
        configs.add(new Object[] { "ca_ra", "ca_ra", "ca_ra", "ca" });
        configs.add(new Object[] { "ca_ra-de", "ca_ra-de", "ca", "ca" });
        configs.add(new Object[] { "ca_ra-ds", "ca", "ca_ra-ds", "ca" });
        configs.add(new Object[] { "ca_ca", "ca_ca", "ca_ca", "ca" });
        configs.add(new Object[] { "ca_ca_ra", "ca_ca_ra", "ca_ca_ra", "ca_ca" });
        configs.add(new Object[] { "ca_ca_ra-de", "ca_ca_ra-de", "ca_ca", "ca_ca" });
        configs.add(new Object[] { "ca_ca_ra-ds", "ca_ca", "ca_ca_ra-ds", "ca" });

        for (Object[] config : configs) {
            Certificate[] chain = testStore
                    .getCertificateChain((String) config[0]);
            List<Certificate> certList = Arrays.asList(chain);
            CertStoreParameters storeParams = new CollectionCertStoreParameters(
                    certList);
            CertStore store = CertStore.getInstance("Collection", storeParams);

            config[0] = store;
            config[1] = "CN=" + config[1];
            config[2] = "CN=" + config[2];
            config[3] = "CN=" + config[3];
        }

        return configs;
    }

    private final CertStore store;
    private final String encryption;
    private final String signing;
    private final String issuer;

    public CertStoreInspectorTest(final CertStore store, final String encryption,
            final String signing, final String issuer) {
        this.store = store;
        this.encryption = encryption;
        this.signing = signing;
        this.issuer = issuer;
    }

    abstract CertStoreInspectorFactory getCertStoreInspectorFactory();

    @Test
    public void example() {
        CertStoreInspector auths = getCertStoreInspectorFactory().getInstance(store);

        Assert.assertEquals(encryption, auths.getRecipient().getSubjectX500Principal()
                .getName());
        Assert.assertEquals(signing, auths.getSigner().getSubjectX500Principal().getName());
        Assert.assertEquals(issuer, auths.getIssuer().getSubjectX500Principal().getName());
    }
}
