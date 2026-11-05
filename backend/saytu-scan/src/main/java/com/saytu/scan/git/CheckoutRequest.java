package com.saytu.scan.git;

import com.saytu.core.git.BranchNames;

import java.net.URI;
import java.util.Objects;

/**
 * What to clone.
 *
 * @param cloneUrl    HTTPS clone URL from discovery, or a {@code file:} URI for LOCAL connections
 * @param branch      branch to check out (validated like {@code git check-ref-format})
 * @param credentials {@code null} for anonymous access and local repositories
 * @param verifyTls   {@code false} only when the connection is explicitly configured that way
 */
public record CheckoutRequest(URI cloneUrl, String branch, GitCredentials credentials, boolean verifyTls) {

    public CheckoutRequest {
        Objects.requireNonNull(cloneUrl, "cloneUrl");
        BranchNames.require(branch);
    }

    @Override
    public String toString() {
        return "CheckoutRequest[" + cloneUrl + "@" + branch + ", credentials=" + (credentials == null ? "none" : credentials)
                + ", verifyTls=" + verifyTls + "]";
    }
}
