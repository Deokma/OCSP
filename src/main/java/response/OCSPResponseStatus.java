package main.java.response;

public enum OCSPResponseStatus {
    SUCCESSFUL(0),
    MALFORMED_REQUEST(1),
    INTERNAL_ERROR(2),
    TRY_LATER(3),
    SIG_REQUIRED(5),
    UNAUTHORIZED(6);
    private int value;

    private OCSPResponseStatus(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }
}