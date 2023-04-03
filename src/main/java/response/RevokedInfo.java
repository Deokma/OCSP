package main.java.response;

import main.java.other.CRLReason;
import main.java.other.GeneralizedTime;

public class RevokedInfo {
    private GeneralizedTime revocationTime;
    private CRLReason revocationReason;

    public RevokedInfo(GeneralizedTime revocationTime, CRLReason revocationReason) {
        this.revocationTime = revocationTime;
        this.revocationReason = revocationReason;
    }

    public GeneralizedTime getRevocationTime() {
        return revocationTime;
    }

    public void setRevocationTime(GeneralizedTime revocationTime) {
        this.revocationTime = revocationTime;
    }

    public CRLReason getRevocationReason() {
        return revocationReason;
    }

    public void setRevocationReason(CRLReason revocationReason) {
        this.revocationReason = revocationReason;
    }
}
