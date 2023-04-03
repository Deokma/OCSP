package main.java.response;

/**
 * @author Denis Popolamov
 */
public class CertStatus {
    private enum StatusType {
        GOOD, REVOKED, UNKNOWN
    }

    private StatusType statusType;
    private RevokedInfo revokedInfo;

    public CertStatus() {
        this.statusType = StatusType.GOOD;
    }

    public CertStatus(RevokedInfo revokedInfo) {
        this.statusType = StatusType.REVOKED;
        this.revokedInfo = revokedInfo;
    }

    public void setUnknownStatus() {
        this.statusType = StatusType.UNKNOWN;
    }

    public boolean isGood() {
        return this.statusType == StatusType.GOOD;
    }

    public boolean isRevoked() {
        return this.statusType == StatusType.REVOKED;
    }

    public boolean isUnknown() {
        return this.statusType == StatusType.UNKNOWN;
    }

    public RevokedInfo getRevokedInfo() {
        return revokedInfo;
    }
}
