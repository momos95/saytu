package com.saytu.scan.lang;

import com.saytu.core.domain.Language;
import com.saytu.core.domain.LanguageProfile;
import com.saytu.scan.TestSupport;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LanguageDetectorTest {

    private Path dir;

    @BeforeEach
    void setUp() throws Exception {
        dir = TestSupport.tempDir("lang");
    }

    @AfterEach
    void tearDown() {
        TestSupport.delete(dir);
    }

    @Test
    void detectsTheLanguagesOfAMixedRepository() throws Exception {
        TestSupport.write(dir, Map.of(
                "api/src/main/java/App.java", "class App {}\n".repeat(50),
                "api/src/main/java/Repo.java", "class Repo {}\n".repeat(50),
                "web/src/app/app.component.ts", "export class A {}\n".repeat(40),
                "web/src/main.ts", "bootstrap();\n",
                "db/V1__init.sql", "create table t (id int);\n".repeat(20),
                "legacy/index.php", "<?php echo 1;\n".repeat(10),
                "native/lib.cpp", "int f() { return 1; }\n".repeat(10),
                "native/lib.h", "int f();\n",
                "Dockerfile", "FROM alpine\n",
                "README.md", "# hello\n"));
        LanguageProfile p = new LanguageDetector().detect(dir);
        assertEquals(2, p.stats().get(Language.JAVA).files());
        assertEquals(2, p.stats().get(Language.TYPESCRIPT).files());
        assertEquals(2, p.stats().get(Language.CPP).files(), "header counted as C++ when there is no C source");
        assertFalse(p.contains(Language.C));
        assertTrue(p.contains(Language.SQL) && p.contains(Language.PHP) && p.contains(Language.DOCKERFILE));
        assertEquals(10, p.analysedFiles());
        assertEquals(Language.JAVA, p.labels().getFirst());
        assertTrue(p.labels().containsAll(List.of(Language.TYPESCRIPT, Language.SQL, Language.PHP, Language.CPP)));
    }

    @Test
    void ignoresDependenciesBuildOutputsAndGeneratedFiles() throws Exception {
        TestSupport.write(dir, Map.of(
                "src/index.js", "console.log(1);\n",
                "node_modules/lodash/lodash.js", "x".repeat(100_000),
                "vendor/acme/lib.php", "<?php\n",
                "target/classes/A.java", "class A {}",
                "dist/main.min.js", "x",
                "src/types.d.ts", "declare const x: number;",
                "obj/Debug/App.cs", "class A {}"));
        LanguageProfile p = new LanguageDetector().detect(dir);
        assertEquals(List.of(Language.JAVASCRIPT), p.labels());
        assertFalse(p.contains(Language.PHP));
        assertFalse(p.contains(Language.JAVA));
        assertFalse(p.contains(Language.CSHARP));
        assertFalse(p.contains(Language.TYPESCRIPT), ".d.ts declarations are generated or third-party typings");
    }

    @Test
    void cHeadersWithCSources() throws Exception {
        TestSupport.write(dir, Map.of("a.c", "int main(){}", "a.h", "int x;", "b.cpp", "int y;"));
        LanguageProfile p = new LanguageDetector().detect(dir);
        assertEquals(2, p.stats().get(Language.C).files());
        assertEquals(1, p.stats().get(Language.CPP).files());
    }

    @Test
    void smallLanguagesAreNotLabelledButStillDetected() throws Exception {
        TestSupport.write(dir, Map.of("App.java", "x".repeat(100_000), "scripts/build.sh", "echo hi\n"));
        LanguageProfile p = new LanguageDetector().detect(dir);
        assertTrue(p.contains(Language.SHELL), "present: tools for it still run");
        assertEquals(List.of(Language.JAVA), p.labels(), "below 1 % and 5 files: no label");
        Files.writeString(dir.resolve("index.html"), "<html></html>");
        assertFalse(new LanguageDetector().detect(dir).labels().contains(Language.HTML), "markup is never a label");
    }

    @Test
    void fileNames() {
        assertEquals(Language.DOCKERFILE, LanguageDetector.languageOf("Dockerfile"));
        assertEquals(Language.DOCKERFILE, LanguageDetector.languageOf("Dockerfile.prod"));
        assertEquals(Language.CSHARP, LanguageDetector.languageOf("Program.cs"));
        assertEquals(Language.SQL, LanguageDetector.languageOf("pkg_body.pkb"));
        assertNull(LanguageDetector.languageOf("app.min.js"));
        assertNull(LanguageDetector.languageOf("LICENSE"));
        assertNull(LanguageDetector.languageOf(".gitignore"));
    }
}
