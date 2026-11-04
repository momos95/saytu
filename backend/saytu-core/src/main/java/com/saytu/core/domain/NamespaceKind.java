package com.saytu.core.domain;

/** Grouping level exposed by a Git provider. Scores "par organisation" are computed on namespaces. */
public enum NamespaceKind {
    /** GitHub organisation. */
    ORGANIZATION,
    /** GitLab top-level group. */
    GROUP,
    /** GitLab sub-group (has a parent namespace). */
    SUBGROUP,
    /** Bitbucket Cloud workspace. */
    WORKSPACE,
    /** Bitbucket Data Center project. */
    PROJECT,
    /** Personal namespace of the token owner. */
    USER,
    /** Directory of local repositories. */
    LOCAL_DIRECTORY
}
