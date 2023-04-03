package main.java.response;

import org.bouncycastle.asn1.ASN1OctetString;

import java.math.BigInteger;
import java.util.Date;

public class OCSPResponse {

    private OCSPResponseStatus responseStatus;
    private ResponseBytes responseBytes;

    public OCSPResponseStatus getResponseStatus() {
        return responseStatus;
    }

    public void setResponseStatus(OCSPResponseStatus responseStatus) {
        this.responseStatus = responseStatus;
    }

    public ResponseBytes getResponseBytes() {
        return responseBytes;
    }

    public void setResponseBytes(ResponseBytes responseBytes) {
        this.responseBytes = responseBytes;
    }

    public static class ResponseBytes {
        private String responseType;
        private byte[] response;

        public String getResponseType() {
            return responseType;
        }

        public void setResponseType(String responseType) {
            this.responseType = responseType;
        }

        public byte[] getResponse() {
            return response;
        }

        public void setResponse(byte[] response) {
            this.response = response;
        }
    }
}

