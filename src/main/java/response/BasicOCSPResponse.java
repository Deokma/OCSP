package main.java.response;

/**
 * @author Denis Popolamov
 */

import main.java.other.AlgorithmIdentifier;
import main.java.other.Certificate;

import java.util.List;

public class BasicOCSPResponse {
    private ResponseData tbsResponseData;
    private AlgorithmIdentifier signatureAlgorithm;
    private byte[] signature;
    private List<Certificate> certs;

    public BasicOCSPResponse(ResponseData tbsResponseData, AlgorithmIdentifier signatureAlgorithm, byte[] signature, List<Certificate> certs) {
        this.tbsResponseData = tbsResponseData;
        this.signatureAlgorithm = signatureAlgorithm;
        this.signature = signature;
        this.certs = certs;
    }

    public ResponseData getTbsResponseData() {
        return tbsResponseData;
    }

    public AlgorithmIdentifier getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public byte[] getSignature() {
        return signature;
    }

    public List<Certificate> getCerts() {
        return certs;
    }
}