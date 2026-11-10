package com.saytu.core.workflow;

import com.saytu.core.scoring.Versions;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Branch and release hygiene of a repository (Git flow conventions), from its remote refs only:
 * <ul>
 *   <li>a production branch {@code main} (or {@code master});</li>
 *   <li>a work branch {@code develop};</li>
 *   <li>releases tagged with a version ({@code v1.4.0}, {@code 1.4.0});</li>
 *   <li>the production branch points exactly at the latest release tag (nothing pushed to production
 *       without a release, no release tagged elsewhere).</li>
 * </ul>
 * Pure function: no network, no clock; tested without Git.
 */
public final class WorkflowCheck {

    public static final List<String> PRODUCTION_BRANCHES = List.of("main", "master");
    public static final String DEVELOP_BRANCH = "develop";
    /** Release tags: optional "v", numbers separated by dots, optional pre-release or build suffix. */
    static final Pattern VERSION_TAG = Pattern.compile("^[vV]?\\d+(\\.\\d+)*([-+][0-9A-Za-z.\\-+]*)?$");

    private WorkflowCheck() {
    }

    public enum Status { PASS, WARN, FAIL }

    public record Check(String id, Status status, String message) {
    }

    /**
     * @param productionSha commit of the production branch, null if absent
     * @param latestTagSha  commit the latest release tag points to (peeled), null if none
     */
    public record Report(Status status, String productionBranch, String productionSha, String developSha,
                         String latestTag, String latestTagSha, int releaseTags, List<Check> checks) {
        public Report {
            checks = List.copyOf(checks);
        }
    }

    /**
     * @param branches branch name → head commit
     * @param tags     tag name → commit it points to (annotated tags already peeled)
     */
    public static Report evaluate(Map<String, String> branches, Map<String, String> tags) {
        Objects.requireNonNull(branches, "branches");
        Objects.requireNonNull(tags, "tags");
        List<Check> checks = new ArrayList<>();

        List<String> production = PRODUCTION_BRANCHES.stream().filter(branches::containsKey).toList();
        String prod = production.isEmpty() ? null : production.getFirst();
        if (prod == null) {
            checks.add(new Check("PRODUCTION_BRANCH", Status.FAIL, "Aucune branche de production main ou master."));
        } else if (production.size() > 1) {
            checks.add(new Check("PRODUCTION_BRANCH", Status.WARN,
                    "Les branches main et master coexistent : main est considérée comme la branche de production ; supprimer l'autre."));
        } else {
            checks.add(new Check("PRODUCTION_BRANCH", Status.PASS, "Branche de production : " + prod + "."));
        }

        String develop = branches.get(DEVELOP_BRANCH);
        if (develop == null) {
            checks.add(new Check("DEVELOP_BRANCH", Status.FAIL,
                    "Pas de branche develop : le travail en cours se fait directement sur la production ou sur des branches isolées."));
        } else if (prod != null && develop.equals(branches.get(prod))) {
            checks.add(new Check("DEVELOP_BRANCH", Status.PASS, "Branche develop présente, identique à " + prod + " (rien en cours)."));
        } else {
            checks.add(new Check("DEVELOP_BRANCH", Status.PASS, "Branche develop présente."));
        }

        List<String> versionTags = tags.keySet().stream().filter(t -> VERSION_TAG.matcher(t).matches()).toList();
        Optional<String> latest = latestRelease(versionTags);
        if (tags.isEmpty()) {
            checks.add(new Check("RELEASE_TAGS", Status.FAIL, "Aucun tag : les versions livrées ne sont pas identifiées."));
        } else if (latest.isEmpty()) {
            checks.add(new Check("RELEASE_TAGS", Status.WARN, tags.size()
                    + " tag(s), aucun au format version (v1.2.3) : impossible de déterminer la dernière version."));
        } else {
            checks.add(new Check("RELEASE_TAGS", Status.PASS, versionTags.size() + " tag(s) de version ; le plus récent est "
                    + latest.get() + "."));
        }

        String prodSha = prod == null ? null : branches.get(prod);
        String tagSha = latest.map(tags::get).orElse(null);
        if (prod == null || latest.isEmpty()) {
            checks.add(new Check("PRODUCTION_ON_LATEST_TAG", Status.WARN,
                    "Alignement non vérifiable : il faut une branche de production et au moins un tag de version."));
        } else if (prodSha.equals(tagSha)) {
            checks.add(new Check("PRODUCTION_ON_LATEST_TAG", Status.PASS, prod + " pointe sur le dernier tag " + latest.get() + "."));
        } else {
            checks.add(new Check("PRODUCTION_ON_LATEST_TAG", Status.FAIL, prod + " (" + shortSha(prodSha)
                    + ") ne pointe pas sur le dernier tag " + latest.get() + " (" + shortSha(tagSha) + ") : des commits ont été "
                    + "poussés sur " + prod + " sans nouvelle version taguée, ou le tag a été posé sur une autre branche."));
        }

        Status overall = checks.stream().map(Check::status).max(Comparator.naturalOrder()).orElse(Status.PASS);
        return new Report(overall, prod, prodSha, develop, latest.orElse(null), tagSha, versionTags.size(), checks);
    }

    /** Highest version; pre-releases (1.2.0-rc1) only when there is no final release. */
    static Optional<String> latestRelease(List<String> versionTags) {
        Comparator<String> byVersion = (a, b) -> Versions.compare(strip(a), strip(b));
        Optional<String> release = versionTags.stream().filter(t -> !strip(t).matches(".*[-+].*")).max(byVersion);
        return release.isPresent() ? release : versionTags.stream().max(byVersion);
    }

    private static String strip(String tag) {
        return tag.startsWith("v") || tag.startsWith("V") ? tag.substring(1) : tag;
    }

    private static String shortSha(String sha) {
        return sha == null ? "?" : sha.substring(0, Math.min(8, sha.length()));
    }
}
