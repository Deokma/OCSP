package main.java.other;

/**
 * @author Denis Popolamov
 */
public class SubjectPublicKeyInfo {
    private AlgorithmIdentifier algorithm;
    private byte[] subjectPublicKey;

    public SubjectPublicKeyInfo(AlgorithmIdentifier algorithm, byte[] subjectPublicKey) {
        this.algorithm = algorithm;
        this.subjectPublicKey = subjectPublicKey;
    }

    public AlgorithmIdentifier getAlgorithm() {
        return algorithm;
    }

    public byte[] getSubjectPublicKey() {
        return subjectPublicKey;
    }
}
