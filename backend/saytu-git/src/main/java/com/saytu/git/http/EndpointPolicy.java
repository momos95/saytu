package com.saytu.git.http;

import com.saytu.core.git.GitProviderException;
import com.saytu.core.git.GitProviderException.Kind;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.Locale;

/**
 * Server-side request forgery guard for every outgoing call to a Git platform.
 * <p>
 * An ADMIN chooses the URL of a connection and the server then sends a token to it, so the
 * destination must be checked before any byte leaves:
 * <ul>
 *   <li>scheme {@code https}; {@code http} only when explicitly allowed (tokens would travel in clear);</li>
 *   <li>never cloud metadata endpoints, link-local, multicast, "this host" or broadcast addresses;</li>
 *   <li>loopback only when allowed (development, tests);</li>
 *   <li>private ranges (10/8, 172.16/12, 192.168/16, fc00::/7) are allowed: self-managed GitLab and
 *       Bitbucket Data Center usually live there.</li>
 * </ul>
 * Every resolved address must pass. Redirects are never followed by {@link GitHttpClient}, so a
 * vetted host cannot bounce the token elsewhere. Residual risk (DNS rebinding between this check and
 * the connection) is documented in docs/security.md.
 */
public final class EndpointPolicy {

    /** Resolves host names; replaceable in tests. */
    @FunctionalInterface
    public interface Resolver {
        InetAddress[] resolve(String host) throws UnknownHostException;
    }

    private final boolean allowPlainHttp;
    private final boolean allowLoopback;
    private final Resolver resolver;

    public EndpointPolicy(boolean allowPlainHttp, boolean allowLoopback, Resolver resolver) {
        this.allowPlainHttp = allowPlainHttp;
        this.allowLoopback = allowLoopback;
        this.resolver = resolver == null ? InetAddress::getAllByName : resolver;
    }

    public static EndpointPolicy strict() {
        return new EndpointPolicy(false, false, null);
    }

    public boolean allowsPlainHttp() {
        return allowPlainHttp;
    }

    /**
     * @throws GitProviderException {@code BLOCKED_BY_POLICY} or {@code UNREACHABLE} (unknown host)
     */
    public void check(URI uri) {
        if (uri == null || uri.getHost() == null) {
            throw blocked("URL has no host");
        }
        if (uri.getUserInfo() != null) {
            throw blocked("credentials must not be embedded in the URL");
        }
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        if (!scheme.equals("https")) {
            if (!scheme.equals("http")) {
                throw blocked("unsupported scheme '" + scheme + "'");
            }
            if (!allowPlainHttp) {
                throw blocked("plain HTTP is disabled because the token would travel unencrypted; use https "
                        + "or set SAYTU_GIT_ALLOW_PLAIN_HTTP=true for an isolated network");
            }
        }
        String host = uri.getHost();
        InetAddress[] addresses;
        try {
            addresses = resolver.resolve(host);
        } catch (UnknownHostException e) {
            throw new GitProviderException(Kind.UNREACHABLE, "Unknown host " + host + " (DNS resolution failed)");
        }
        if (addresses == null || addresses.length == 0) {
            throw new GitProviderException(Kind.UNREACHABLE, "Unknown host " + host + " (no address)");
        }
        for (InetAddress address : addresses) {
            String reason = forbiddenReason(address);
            if (reason != null) {
                throw blocked(host + " resolves to " + address.getHostAddress() + " (" + reason + ")");
            }
        }
    }

    private String forbiddenReason(InetAddress a) {
        byte[] b = a.getAddress();
        if (a.isAnyLocalAddress()) {
            return "unspecified address";
        }
        if (a.isLoopbackAddress()) {
            return allowLoopback ? null : "loopback address; set SAYTU_GIT_ALLOW_LOOPBACK=true for development only";
        }
        if (a.isLinkLocalAddress()) {
            return "link-local address, used by cloud metadata services";
        }
        if (a.isMulticastAddress()) {
            return "multicast address";
        }
        if (b.length == 4) {
            int first = b[0] & 0xff;
            if (first == 0) {
                return "'this network' address";
            }
            if ((b[0] & 0xff) == 255 && (b[1] & 0xff) == 255 && (b[2] & 0xff) == 255 && (b[3] & 0xff) == 255) {
                return "broadcast address";
            }
            // Alibaba Cloud metadata endpoint
            if (first == 100 && (b[1] & 0xff) == 100 && (b[2] & 0xff) == 100 && (b[3] & 0xff) == 200) {
                return "cloud metadata address";
            }
        }
        if (a instanceof Inet6Address) {
            // AWS IMDS over IPv6: fd00:ec2::254
            if ((b[0] & 0xff) == 0xfd && b[1] == 0 && (b[2] & 0xff) == 0x0e && (b[3] & 0xff) == 0xc2
                    && isZero(b, 4, 14) && (b[14] & 0xff) == 0x02 && (b[15] & 0xff) == 0x54) {
                return "cloud metadata address";
            }
        }
        return null;
    }

    private static boolean isZero(byte[] b, int from, int to) {
        for (int i = from; i < to; i++) {
            if (b[i] != 0) {
                return false;
            }
        }
        return true;
    }

    private static GitProviderException blocked(String detail) {
        return new GitProviderException(Kind.BLOCKED_BY_POLICY, "Destination refused: " + detail);
    }
}
