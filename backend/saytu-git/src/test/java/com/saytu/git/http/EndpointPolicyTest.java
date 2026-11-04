package com.saytu.git.http;

import com.saytu.core.git.GitProviderException;
import com.saytu.core.git.GitProviderException.Kind;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EndpointPolicyTest {

    /** Fake DNS: host -> addresses, so tests never hit the network. */
    private static EndpointPolicy.Resolver dns(Map<String, String> table) {
        return host -> {
            String ip = table.get(host);
            if (ip == null) {
                throw new UnknownHostException(host);
            }
            return new InetAddress[]{InetAddress.getByName(ip)};
        };
    }

    private final Map<String, String> table = Map.of(
            "gitlab.corp.local", "10.1.2.3",
            "github.com", "140.82.121.4",
            "metadata", "169.254.169.254",
            "alibaba", "100.100.100.200",
            "aws6", "fd00:ec2::254",
            "localhost", "127.0.0.1",
            "zero", "0.0.0.0",
            "ula", "fd12:3456::1");

    private final EndpointPolicy strict = new EndpointPolicy(false, false, dns(table));

    private Kind kindOf(EndpointPolicy p, String url) {
        return assertThrows(GitProviderException.class, () -> p.check(URI.create(url))).kind();
    }

    @Test
    void allowsPublicAndPrivateNetworkHttpsHosts() {
        assertDoesNotThrow(() -> strict.check(URI.create("https://github.com/api")));
        assertDoesNotThrow(() -> strict.check(URI.create("https://gitlab.corp.local:8443/api/v4")));
        assertDoesNotThrow(() -> strict.check(URI.create("https://ula/")));
    }

    @Test
    void blocksMetadataLinkLocalAndSpecialAddresses() {
        for (String host : List.of("metadata", "alibaba", "aws6", "zero")) {
            assertEquals(Kind.BLOCKED_BY_POLICY, kindOf(strict, "https://" + host + "/"), host);
        }
    }

    @Test
    void loopbackOnlyWhenAllowed() {
        var e = assertThrows(GitProviderException.class, () -> strict.check(URI.create("https://localhost/")));
        assertTrue(e.getMessage().contains("SAYTU_GIT_ALLOW_LOOPBACK"));
        assertDoesNotThrow(() -> new EndpointPolicy(false, true, dns(table)).check(URI.create("https://localhost/")));
    }

    @Test
    void plainHttpOnlyWhenAllowed() {
        var e = assertThrows(GitProviderException.class, () -> strict.check(URI.create("http://github.com/")));
        assertEquals(Kind.BLOCKED_BY_POLICY, e.kind());
        assertTrue(e.getMessage().contains("SAYTU_GIT_ALLOW_PLAIN_HTTP"));
        assertDoesNotThrow(() -> new EndpointPolicy(true, false, dns(table)).check(URI.create("http://github.com/")));
    }

    @Test
    void rejectsOtherSchemesCredentialsAndUnknownHosts() {
        assertEquals(Kind.BLOCKED_BY_POLICY, kindOf(strict, "file:///etc/passwd"));
        assertEquals(Kind.BLOCKED_BY_POLICY, kindOf(strict, "ftp://github.com/"));
        assertEquals(Kind.BLOCKED_BY_POLICY, kindOf(strict, "https://u:p@github.com/"));
        assertEquals(Kind.UNREACHABLE, kindOf(strict, "https://nowhere.invalid/"));
    }

    @Test
    void everyResolvedAddressMustPass() {
        EndpointPolicy mixed = new EndpointPolicy(false, false, host -> new InetAddress[]{
                InetAddress.getByName("140.82.121.4"), InetAddress.getByName("169.254.169.254")});
        assertEquals(Kind.BLOCKED_BY_POLICY, kindOf(mixed, "https://rebind.example/"));
    }
}
