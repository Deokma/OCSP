package main.java.other;

/**
 * @author Denis Popolamov
 */
import java.math.BigInteger;

public class CertificateSerialNumber {
    private BigInteger value;

    public CertificateSerialNumber(BigInteger value) {
        this.value = value;
    }

    public BigInteger getValue() {
        return value;
    }

    public void setValue(BigInteger value) {
        this.value = value;
    }
}
