package main.java.response;

import main.java.other.KeyHash;
import main.java.other.Name;

/**
 * @author Denis Popolamov
 */
public class ResponderID {

    private Name byName;
    private KeyHash byKey;

    public ResponderID(Name byName) {
        this.byName = byName;
    }

    public ResponderID(KeyHash byKey) {
        this.byKey = byKey;
    }

    public Name getByName() {
        return byName;
    }

    public KeyHash getByKey() {
        return byKey;
    }

    public boolean isByName() {
        return byName != null;
    }

    public boolean isByKey() {
        return byKey != null;
    }
}
