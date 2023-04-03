package main.java.request;

import main.java.other.Extensions;
import main.java.other.GeneralName;

import java.util.ArrayList;

/**
 * @author Denis Popolamov
 */
class OCSPRequest {
    private TBSRequest tbsRequest;
    private Signature optionalSignature;

    public OCSPRequest(TBSRequest tbsRequest) {
        this.tbsRequest = tbsRequest;
    }

    public TBSRequest getTbsRequest() {
        return tbsRequest;
    }

    public void setTbsRequest(TBSRequest tbsRequest) {
        this.tbsRequest = tbsRequest;
    }

    public Signature getOptionalSignature() {
        return optionalSignature;
    }

    public void setOptionalSignature(Signature optionalSignature) {
        this.optionalSignature = optionalSignature;
    }

    public static class TBSRequest {
        private int version;
        private GeneralName requestorName;
        private ArrayList<Request> requestList;
        private Extensions requestExtensions;

        public TBSRequest(int version, GeneralName requestorName, ArrayList<Request> requestList,
                          Extensions requestExtensions) {
            this.version = version;
            this.requestorName = requestorName;
            this.requestList = requestList;
            this.requestExtensions = requestExtensions;
        }

        public int getVersion() {
            return version;
        }

        public void setVersion(int version) {
            this.version = version;
        }

        public GeneralName getRequestorName() {
            return requestorName;
        }

        public void setRequestorName(GeneralName requestorName) {
            this.requestorName = requestorName;
        }

        public ArrayList<Request> getRequestList() {
            return requestList;
        }

        public void setRequestList(ArrayList<Request> requestList) {
            this.requestList = requestList;
        }

        public Extensions getRequestExtensions() {
            return requestExtensions;
        }

        public void setRequestExtensions(Extensions requestExtensions) {
            this.requestExtensions = requestExtensions;
        }

        public static class Request {
            private CertID reqCert;

            public Request(CertID reqCert) {
                this.reqCert = reqCert;
            }

            public CertID getReqCert() {
                return reqCert;
            }

            public void setReqCert(CertID reqCert) {
                this.reqCert = reqCert;
            }
        }
    }
}