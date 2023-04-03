package main.java.other;

public class Certificate {
    private TBSCertificate tbsCertificate;
    private AlgorithmIdentifier signatureAlgorithm;
    private byte[] signature;

    public Certificate(TBSCertificate tbsCertificate, AlgorithmIdentifier signatureAlgorithm, byte[] signature) {
        this.tbsCertificate = tbsCertificate;
        this.signatureAlgorithm = signatureAlgorithm;
        this.signature = signature;
    }

    public TBSCertificate getTbsCertificate() {
        return tbsCertificate;
    }

    public AlgorithmIdentifier getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public byte[] getSignature() {
        return signature;
    }
}