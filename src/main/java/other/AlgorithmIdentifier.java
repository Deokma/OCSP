package main.java.other;

/**
 * @author Denis Popolamov
 */
public class AlgorithmIdentifier {
    private final String algorithm;
    private final byte[] parameters;

    public AlgorithmIdentifier(String algorithm, byte[] parameters) {
        this.algorithm = algorithm;
        this.parameters = parameters;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public byte[] getParameters() {
        return parameters;
    }
}
