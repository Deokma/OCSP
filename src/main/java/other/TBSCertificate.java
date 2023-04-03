package main.java.other;

public class TBSCertificate {
    private int version;
    private int serialNumber;
    private AlgorithmIdentifier signature;
    private Name issuer;
    private Validity validity;
    private Name subject;
    private SubjectPublicKeyInfo subjectPublicKeyInfo;
    private UniqueIdentifier issuerUniqueID;
    private UniqueIdentifier subjectUniqueID;
    private Extensions extensions;

    public TBSCertificate(int version, int serialNumber, AlgorithmIdentifier signature, Name issuer,
                          Validity validity, Name subject, SubjectPublicKeyInfo subjectPublicKeyInfo,
                          UniqueIdentifier issuerUniqueID, UniqueIdentifier subjectUniqueID, Extensions extensions) {
        this.version = version;
        this.serialNumber = serialNumber;
        this.signature = signature;
        this.issuer = issuer;
        this.validity = validity;
        this.subject = subject;
        this.subjectPublicKeyInfo = subjectPublicKeyInfo;
        this.issuerUniqueID = issuerUniqueID;
        this.subjectUniqueID = subjectUniqueID;
        this.extensions = extensions;
    }

    public int getVersion() {
        return version;
    }

    public int getSerialNumber() {
        return serialNumber;
    }

    public AlgorithmIdentifier getSignature() {
        return signature;
    }

    public Name getIssuer() {
        return issuer;
    }

    public Validity getValidity() {
        return validity;
    }

    public Name getSubject() {
        return subject;
    }

    public SubjectPublicKeyInfo getSubjectPublicKeyInfo() {
        return subjectPublicKeyInfo;
    }

    public UniqueIdentifier getIssuerUniqueID() {
        return issuerUniqueID;
    }

    public UniqueIdentifier getSubjectUniqueID() {
        return subjectUniqueID;
    }

    public Extensions getExtensions() {
        return extensions;
    }
}
