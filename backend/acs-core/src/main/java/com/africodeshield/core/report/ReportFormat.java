package com.africodeshield.core.report;

/** Export formats (implemented in phase 6). */
public enum ReportFormat {
    HTML("text/html", "html"),
    PDF("application/pdf", "pdf"),
    JSON("application/json", "json"),
    /** SARIF 2.1.0, for import into IDEs and code-scanning tools. */
    SARIF("application/sarif+json", "sarif");

    private final String mediaType;
    private final String extension;

    ReportFormat(String mediaType, String extension) {
        this.mediaType = mediaType;
        this.extension = extension;
    }

    public String mediaType() {
        return mediaType;
    }

    public String extension() {
        return extension;
    }
}
