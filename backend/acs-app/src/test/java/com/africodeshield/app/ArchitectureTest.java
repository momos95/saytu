package com.africodeshield.app;

import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;
import static com.tngtech.archunit.library.dependencies.SlicesRuleDefinition.slices;

/** Guards the modular-monolith boundaries described in docs/architecture.md. */
@AnalyzeClasses(packages = "com.africodeshield", importOptions = ImportOption.DoNotIncludeTests.class)
class ArchitectureTest {

    @ArchTest
    static final ArchRule coreIsFrameworkFree = noClasses()
            .that().resideInAPackage("com.africodeshield.core..")
            .should().dependOnClassesThat().resideInAnyPackage(
                    "org.springframework..", "jakarta..", "org.hibernate..", "com.fasterxml..", "java.sql..")
            .because("acs-core holds the domain and the ports; adapters live in acs-app");

    @ArchTest
    static final ArchRule gitProvidersAreFrameworkFree = noClasses()
            .that().resideInAPackage("com.africodeshield.git..")
            .should().dependOnClassesThat().resideInAnyPackage(
                    "org.springframework..", "jakarta..", "org.hibernate..", "com.fasterxml..", "com.africodeshield.app..")
            .because("acs-git handles tokens and talks to external hosts: no transitive dependency (ADR-0005)");

    @ArchTest
    static final ArchRule onlyTheVaultUsesTheCipher = noClasses()
            .that().resideInAPackage("com.africodeshield.app..")
            .and().resideOutsideOfPackages("com.africodeshield.app.vault..", "com.africodeshield.app.web..",
                    "com.africodeshield.app.source..")
            .should().dependOnClassesThat().haveSimpleName("TokenCipher")
            .because("secrets are encrypted and decrypted through TokenVault only");

    @ArchTest
    static final ArchRule coreDoesNotDependOnApp = noClasses()
            .that().resideInAPackage("com.africodeshield.core..")
            .should().dependOnClassesThat().resideInAPackage("com.africodeshield.app..");

    @ArchTest
    static final ArchRule noCyclesBetweenFeatures = slices()
            .matching("com.africodeshield.app.(*)..")
            .should().beFreeOfCycles();

    @ArchTest
    static final ArchRule entitiesStayOutOfTheWebLayer = noClasses()
            .that().haveSimpleNameEndingWith("Controller")
            .should().dependOnClassesThat().haveSimpleNameEndingWith("Entity")
            .orShould().dependOnClassesThat().resideInAPackage("jakarta.persistence..")
            .because("controllers expose DTOs (records), never JPA entities")
            .allowEmptyShould(true);

    @ArchTest
    static final ArchRule entityMethodsAreProxyable = com.tngtech.archunit.lang.syntax.ArchRuleDefinition.methods()
            .that().areDeclaredInClassesThat().areAnnotatedWith(jakarta.persistence.Entity.class)
            .and().arePublic()
            .should().notHaveModifier(com.tngtech.archunit.core.domain.JavaModifier.FINAL)
            .because("Hibernate cannot create lazy-loading proxies for entities with final public methods");

    @ArchTest
    static final ArchRule repositoriesAreInterfaces = classes()
            .that().haveSimpleNameEndingWith("Repository").and().resideInAPackage("com.africodeshield.app..")
            .should().beInterfaces();
}
