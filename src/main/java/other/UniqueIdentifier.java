package main.java.other;

/**
 * @author Denis Popolamov
 */
public class UniqueIdentifier {
    private byte[] value;

    public UniqueIdentifier(byte[] value) {
        this.value = value;
    }

    public byte[] getValue() {
        return value;
    }

    public void setValue(byte[] value) {
        this.value = value;
    }
}
