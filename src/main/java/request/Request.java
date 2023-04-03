package main.java.request;

import main.java.other.Extensions;

import java.util.List;

/**
 * @author Denis Popolamov
 */
public class Request {
    CertID certID;
    List<Extensions> singleRequestExtensions;

    public Request(CertID certID, List<Extensions> singleRequestExtensions) {
        this.certID = certID;
        this.singleRequestExtensions = singleRequestExtensions;
    }

    public CertID getCertID() {
        return certID;
    }

    public void setCertID(CertID certID) {
        this.certID = certID;
    }

    public List<Extensions> getSingleRequestExtensions() {
        return singleRequestExtensions;
    }

    public void setSingleRequestExtensions(List<Extensions> singleRequestExtensions) {
        this.singleRequestExtensions = singleRequestExtensions;
    }
}
