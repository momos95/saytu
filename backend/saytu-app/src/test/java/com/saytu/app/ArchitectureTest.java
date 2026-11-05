package com.saytu.app;

import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;
import static com.tngtech.archunit.library.dependencies.SlicesRuleDefinition.slices;

/** Guards the modular-monolith boundaries described in docs/architecture.md. */
@AnalyzeClasses(packages = "com.saytu", importOptions = ImportOption.DoNotIncludeTests.class)
class ArchitectureTest {

    @ArchTest
    static final ArchRule coreIsFrameworkFree = noClasses()
            .that().resideInAPackage("com.saytu.core..")
            .should().dependOnClassesThat().resideInAnyPackage(
                    "org.springframework..", "jakarta..", "org.hibernate..", "com.fasterxml..", "java.sql..")
            .because("saytu-core holds the domain and the ports; adapters live in saytu-app");

    @ArchTest
    static final ArchRule gitProvidersAreFrameworkFree = noClasses()
            .that().resideInAPackage("com.saytu.git..")
            .should().dependOnClassesThat().resideInAnyPackage(
                    "org.springframework..", "jakarta..", "org.hibernate..", "com.fasterxml..", "com.saytu.app..")
            .because("saytu-git handles tokens and talks to external hosts: no transitive dependency (ADR-0005)");

    @ArchTest
    static final ArchRule scanEngineIsFrameworkFree = noClasses()
            .that().resideInAPackage("com.saytu.scan..")
            .should().dependOnClassesThat().resideInAnyPackage(
                    "org.springframework..", "jakarta..", "org.hibernate..", "com.fasterxml..", "com.saytu.app..")
            .because("saytu-scan runs untrusted repositories through external tools: JDK only, like saytu-git");

    @ArchTest
    static final ArchRule onlyTheVaultUsesTheCipher = noClasses()
            .that().resideInAPackage("com.saytu.app..")
            .and().resideOutsideOfPackages("com.saytu.app.vault..", "com.saytu.app.web..",
                    "com.saytu.app.source..")
            .should().dependOnClassesThat().haveSimpleName("TokenCipher")
            .because("secrets are encrypted and decrypted through TokenVault only");

    @ArchTest
    static final ArchRule coreDoesNotDependOnApp = noClasses()
            .that().resideInAPackage("com.saytu.core..")
            .should().dependOnClassesThat().resideInAPackage("com.saytu.app..");

    @ArchTest
    static final ArchRule noCyclesBetweenFeatures = slices()
            .matching("com.saytu.app.(*)..")
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
            .that().haveSimpleNameEndingWith("Repository").and().resideInAPackage("com.saytu.app..")
            .should().beInterfaces();
}
