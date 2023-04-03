package main.java.request;

/**
 * @author Denis Popolamov
 */
import main.java.other.AlgorithmIdentifier;
import main.java.other.Certificate;

import java.util.List;

public class Signature {
    private AlgorithmIdentifier signatureAlgorithm;
    private byte[] signature;
    private List<Certificate> certs;

    public Signature(AlgorithmIdentifier signatureAlgorithm, byte[] signature, List<Certificate> certs) {
        this.signatureAlgorithm = signatureAlgorithm;
        this.signature = signature;
        this.certs = certs;
    }

    public AlgorithmIdentifier getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(AlgorithmIdentifier signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public byte[] getSignature() {
        return signature;
    }

    public void setSignature(byte[] signature) {
        this.signature = signature;
    }

    public List<Certificate> getCerts() {
        return certs;
    }

    public void setCerts(List<Certificate> certs) {
        this.certs = certs;
    }
}
