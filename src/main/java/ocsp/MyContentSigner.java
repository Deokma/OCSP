package ocsp;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.RuntimeOperatorException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;

import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;

public class MyContentSigner implements ContentSigner {

    private final AlgorithmIdentifier algorithmIdentifier;
    private final DigestCalculator digestCalculator;
    private final BcRSAContentSignerBuilder signerBuilder;
    private final PrivateKey privateKey;
    private OutputStream outputStream;

    public MyContentSigner(PrivateKey privateKey, AlgorithmIdentifier algorithmIdentifier, DigestCalculator digestCalculator) throws GeneralSecurityException {
        this.privateKey = privateKey;
        this.algorithmIdentifier = algorithmIdentifier;
        this.digestCalculator = digestCalculator;
        this.signerBuilder = new BcRSAContentSignerBuilder(algorithmIdentifier, (AlgorithmIdentifier) digestCalculator);
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return algorithmIdentifier;
    }

    @Override
    public OutputStream getOutputStream() {
        if (outputStream == null) {
            outputStream = new OutputStream() {
                @Override
                public void write(int b) throws IOException {
                    // do nothing
                }

                @Override
                public void write(byte[] b, int off, int len) throws IOException {
                    digestCalculator.getOutputStream().write(b, off, len);
                }

                @Override
                public void close() throws IOException {
                    // do nothing
                }
            };
        }
        return outputStream;
    }

    @Override
    public byte[] getSignature() {
        try {
            return signerBuilder.build((AsymmetricKeyParameter) privateKey).getSignature();
        } catch (OperatorCreationException e) {
            throw new RuntimeOperatorException("exception obtaining signature: " + e.getMessage(), e);
        }
    }

}

