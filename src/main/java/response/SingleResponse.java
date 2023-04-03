package main.java.response;

/**
 * @author Denis Popolamov
 */
import main.java.other.AlgorithmIdentifier;
import main.java.other.Extensions;
import main.java.other.GeneralizedTime;
import main.java.request.CertID;

import java.math.BigInteger;
import java.util.Date;

public class SingleResponse {
    private CertID certID;
    private CertStatus certStatus;
    private GeneralizedTime thisUpdate;
    private GeneralizedTime nextUpdate;
    private Extensions singleExtensions;

    public SingleResponse(CertID certID, CertStatus certStatus, GeneralizedTime thisUpdate, GeneralizedTime nextUpdate, Extensions singleExtensions) {
        this.certID = certID;
        this.certStatus = certStatus;
        this.thisUpdate = thisUpdate;
        this.nextUpdate = nextUpdate;
        this.singleExtensions = singleExtensions;
    }

    public CertID getCertID() {
        return certID;
    }

    public void setCertID(CertID certID) {
        this.certID = certID;
    }

    public CertStatus getCertStatus() {
        return certStatus;
    }

    public void setCertStatus(CertStatus certStatus) {
        this.certStatus = certStatus;
    }

    public GeneralizedTime getThisUpdate() {
        return thisUpdate;
    }

    public void setThisUpdate(GeneralizedTime thisUpdate) {
        this.thisUpdate = thisUpdate;
    }

    public GeneralizedTime getNextUpdate() {
        return nextUpdate;
    }

    public void setNextUpdate(GeneralizedTime nextUpdate) {
        this.nextUpdate = nextUpdate;
    }

    public Extensions getSingleExtensions() {
        return singleExtensions;
    }

    public void setSingleExtensions(Extensions singleExtensions) {
        this.singleExtensions = singleExtensions;
    }
}
