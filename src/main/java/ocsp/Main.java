package ocsp;

import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.operator.OperatorCreationException;

import javax.crypto.SecretKey;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * @author Denis Popolamov
 */
public class Main {

    public static void createCertificate() throws NoSuchAlgorithmException, NoSuchProviderException, CertificateException, OperatorCreationException, IOException {
        CertificateAuthority ca = new CertificateAuthority();
       // ca.savePrivateKey("caPrivateKey.pem");
        // Создание самоподписанного сертификата
        X509Certificate selfSignedCert = ca.createSelfSignedCertificate(new Date(), new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000L));

        // Выдача сертификата клиенту
        PublicKey publicKey = ca.getPublicKey();
        ca.savePrivateKey("clientPrivateKey.pem");

        X509Certificate clientCert = ca.issueCertificate(publicKey, new Date(), new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000L));
        FileOutputStream fos = new FileOutputStream("clientCert.crt");
        fos.write(clientCert.getEncoded());
        fos.close();
        FileOutputStream fos1 = new FileOutputStream("caCert.crt");
        fos1.write(selfSignedCert.getEncoded());
        fos1.close();
        System.out.println(clientCert.toString());
    }

    public static void main(String[] args) throws CertificateException, NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException, IOException {
        createCertificate();
    }
}

