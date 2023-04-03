package main.java.other;

public class KeyHash {
    private byte[] hashValue;

    public KeyHash(byte[] hashValue) {
        this.hashValue = hashValue;
    }

    public byte[] getHashValue() {
        return hashValue;
    }

    public void setHashValue(byte[] hashValue) {
        this.hashValue = hashValue;
    }
}
