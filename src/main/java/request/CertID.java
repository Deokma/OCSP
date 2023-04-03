package main.java.request;

/**
 * @author Denis Popolamov
 */
import main.java.other.AlgorithmIdentifier;

import java.math.BigInteger;

public class CertID {
    private AlgorithmIdentifier hashAlgorithm;
    private byte[] issuerNameHash;
    private byte[] issuerKeyHash;
    private BigInteger serialNumber;

    public CertID(AlgorithmIdentifier hashAlgorithm, byte[] issuerNameHash, byte[] issuerKeyHash, BigInteger serialNumber) {
        this.hashAlgorithm = hashAlgorithm;
        this.issuerNameHash = issuerNameHash;
        this.issuerKeyHash = issuerKeyHash;
        this.serialNumber = serialNumber;
    }

    public AlgorithmIdentifier getHashAlgorithm() {
        return hashAlgorithm;
    }

    public byte[] getIssuerNameHash() {
        return issuerNameHash;
    }

    public byte[] getIssuerKeyHash() {
        return issuerKeyHash;
    }

    public BigInteger getSerialNumber() {
        return serialNumber;
    }
}
