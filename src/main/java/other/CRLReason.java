package main.java.other;

public enum CRLReason {
    unspecified(0),
    keyCompromise(1),
    cACompromise(2),
    affiliationChanged(3),
    superseded(4),
    cessationOfOperation(5),
    certificateHold(6),
    removeFromCRL(8),
    privilegeWithdrawn(9),
    aACompromise(10);

    private int value;

    private CRLReason(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }
}
