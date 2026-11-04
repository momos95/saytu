package com.saytu.git.http;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * TLS trust for Git platforms: the JVM default trust store, plus optionally the certificates of an
 * internal CA (PEM bundle, {@code SAYTU_GIT_CA_BUNDLE}). Certificate verification can never be turned
 * off: self-signed instances are supported by trusting their certificate explicitly.
 */
public final class TrustConfig {

    private TrustConfig() {
    }

    public static SSLContext create(Path extraCaBundle) {
        try {
            if (extraCaBundle == null) {
                return SSLContext.getDefault();
            }
            List<X509Certificate> extra = loadPem(extraCaBundle);
            if (extra.isEmpty()) {
                throw new IllegalArgumentException("No certificate found in " + extraCaBundle);
            }
            KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
            store.load(null, null);
            for (int i = 0; i < extra.size(); i++) {
                store.setCertificateEntry("saytu-extra-" + i, extra.get(i));
            }
            X509TrustManager custom = trustManager(store);
            X509TrustManager system = trustManager(null);
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, new TrustManager[]{new CompositeTrustManager(system, custom)}, null);
            return context;
        } catch (GeneralSecurityException | IOException e) {
            throw new IllegalStateException("Cannot build TLS trust from " + extraCaBundle + ": " + e.getMessage(), e);
        }
    }

    static List<X509Certificate> loadPem(Path bundle) throws IOException, CertificateException {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        try (InputStream in = Files.newInputStream(bundle)) {
            Collection<? extends java.security.cert.Certificate> certs = factory.generateCertificates(in);
            List<X509Certificate> result = new ArrayList<>();
            for (var c : certs) {
                result.add((X509Certificate) c);
            }
            return result;
        }
    }

    private static X509TrustManager trustManager(KeyStore store) throws GeneralSecurityException {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(store);
        for (TrustManager tm : tmf.getTrustManagers()) {
            if (tm instanceof X509TrustManager x) {
                return x;
            }
        }
        throw new IllegalStateException("No X509TrustManager available");
    }

    /** Accepts a server chain trusted by either the system store or the extra CA bundle. */
    static final class CompositeTrustManager implements X509TrustManager {
        private final X509TrustManager first;
        private final X509TrustManager second;

        CompositeTrustManager(X509TrustManager first, X509TrustManager second) {
            this.first = first;
            this.second = second;
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            throw new CertificateException("Client authentication is not supported");
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            try {
                first.checkServerTrusted(chain, authType);
            } catch (CertificateException e) {
                second.checkServerTrusted(chain, authType);
            }
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            X509Certificate[] a = first.getAcceptedIssuers();
            X509Certificate[] b = second.getAcceptedIssuers();
            X509Certificate[] all = new X509Certificate[a.length + b.length];
            System.arraycopy(a, 0, all, 0, a.length);
            System.arraycopy(b, 0, all, a.length, b.length);
            return all;
        }
    }
}
