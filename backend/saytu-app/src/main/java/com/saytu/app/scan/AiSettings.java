package com.saytu.app.scan;

import java.net.URI;
import java.util.Locale;

/**
 * Local AI settings (app_setting 'ai.ollama'). The base URL must point to a server of the installation
 * (by default the optional "ollama" container): findings are never sent to an external service.
 */
public record AiSettings(boolean enabled, String baseUrl, String model, int timeoutSeconds) {

    public static final AiSettings DEFAULT = new AiSettings(false, "http://ollama:11434", "qwen2.5-coder:7b", 120);

    /** Validated copy; IllegalArgumentException with a user-facing message. */
    public AiSettings validated() {
        String url = baseUrl == null ? "" : baseUrl.strip();
        URI uri;
        try {
            uri = URI.create(url);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("URL d'Ollama invalide");
        }
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        if (!(scheme.equals("http") || scheme.equals("https")) || uri.getHost() == null || uri.getRawUserInfo() != null
                || uri.getRawQuery() != null) {
            throw new IllegalArgumentException("URL d'Ollama invalide : http(s)://hôte:port attendu");
        }
        String m = model == null ? "" : model.strip();
        if (!m.matches("[A-Za-z0-9._:/-]{1,100}")) {
            throw new IllegalArgumentException("Nom de modèle invalide (ex. qwen2.5-coder:7b)");
        }
        if (timeoutSeconds < 10 || timeoutSeconds > 600) {
            throw new IllegalArgumentException("Délai entre 10 et 600 secondes");
        }
        return new AiSettings(enabled, url.endsWith("/") ? url.substring(0, url.length() - 1) : url, m, timeoutSeconds);
    }
}
