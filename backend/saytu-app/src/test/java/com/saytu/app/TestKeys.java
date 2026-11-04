package com.saytu.app;

/** Fixed, test-only master key (32 bytes, base64). Never use outside tests. */
public final class TestKeys {

    public static final String MASTER_KEY = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    public static final String MASTER_KEY_PROPERTY = "saytu.vault.master-key=" + MASTER_KEY;

    private TestKeys() {
    }
}
