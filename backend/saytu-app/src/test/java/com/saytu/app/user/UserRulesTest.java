package com.saytu.app.user;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class UserRulesTest {

    @Test
    void rolesAndIdsAreChecked() {
        assertEquals("AUDITOR", UserService.role(" auditor "));
        assertThrows(IllegalArgumentException.class, () -> UserService.role("ROOT"));
        assertThrows(IllegalArgumentException.class, () -> UserService.role(null));
        UserService.checkId("0b8f1a52-2c4e-4f38-9a3d-6f2d1c7e8a90");
        assertThrows(IllegalArgumentException.class, () -> UserService.checkId("../../realms/master"));
    }

    @Test
    void temporaryPasswordsAreStrongAndUnique() {
        UserService users = new UserService(null, null);
        String a = users.temporaryPassword();
        String b = users.temporaryPassword();
        assertNotEquals(a, b);
        assertEquals(22, a.length());
        assertTrue(a.chars().anyMatch(Character::isUpperCase) && a.chars().anyMatch(Character::isLowerCase)
                && a.chars().anyMatch(Character::isDigit), "Keycloak default policy: upper, lower, digit");
        assertFalse(a.contains("0") || a.contains("O") || a.contains("l") || a.contains("1"), "no ambiguous characters");
    }
}
