package demo;

import java.util.*;

/** Deliberately poor code used by SAYTU's quality scanner tests. */
public class Order {
    private String status;

    public boolean isPaid() {
        return status == "PAID";
    }

    public void load(String raw) {
        try {
            status = raw.trim();
        } catch (Exception e) {
        }
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof Order other && Objects.equals(status, other.status);
    }
}
