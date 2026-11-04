package com.saytu.app.config;

import java.util.Set;

/**
 * Application roles, defined as Keycloak realm roles.
 * <ul>
 *   <li>ADMIN: Git connections, users, settings, scanner configuration, everything below;</li>
 *   <li>AUDITOR: launches scans, triages findings, generates reports, everything below;</li>
 *   <li>VIEWER: read-only access to dashboards, findings and reports.</li>
 * </ul>
 * Composite roles in Keycloak make ADMIN include AUDITOR and AUDITOR include VIEWER, so checks
 * can use the minimum role required.
 */
public final class Roles {

    public static final String ADMIN = "ADMIN";
    public static final String AUDITOR = "AUDITOR";
    public static final String VIEWER = "VIEWER";

    public static final Set<String> ALL = Set.of(ADMIN, AUDITOR, VIEWER);

    /** Spring Security authority prefix. */
    public static final String PREFIX = "ROLE_";

    private Roles() {
    }
}
