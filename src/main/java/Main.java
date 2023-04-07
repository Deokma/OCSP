import ca.CertificateAuthority;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;

/**
 * @author Denis Popolamov
 */
public class Main {

    public static void createCertificate(FileInputStream file, CertificateAuthority ca) throws NoSuchAlgorithmException, NoSuchProviderException, CertificateException, OperatorCreationException, IOException, InvalidKeySpecException {
        //CertificateFactory cf = CertificateFactory.getInstance("X.509");
        // X509Certificate existingCert = (X509Certificate) cf.generateCertificate(file);
       // FileInputStream caPublicKeyFile = new FileInputStream("caPublicKey.pem");
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate caCert = (X509Certificate) cf.generateCertificate(file);
        PublicKey caPublicKey = caCert.getPublicKey();
        file.close();
        // Создание нового сертификата, основанного на существующем
        //PublicKey publicKey = existingCert.getPublicKey();

       X509Certificate clientCert = ca.issueCertificate(caPublicKey, new Date(), new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000L), "Name");
       // X509Certificate clientCert = ca.createSelfSignedCertificate(new Date(System.currentTimeMillis()), new Date(System.currentTimeMillis()));
        // Сохранение нового сертификата в файл
        FileOutputStream fos = new FileOutputStream("clientCert.crt");
        fos.write(clientCert.getEncoded());
        fos.close();
    }

    public static void createSelfSignedCert(CertificateAuthority ca) throws NoSuchAlgorithmException, NoSuchProviderException, IOException, CertificateException, OperatorCreationException {
        // Создание самоподписанного сертификата
        X509Certificate selfSignedCert = ca.createSelfSignedCertificate(new Date(), new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000L));
        //X509Certificate selfSignedCert = ca.createSelfSignedCertificate(new Date(System.currentTimeMillis()), new Date(System.currentTimeMillis()));
        FileOutputStream caCertFile = new FileOutputStream("caCert.crt");
        caCertFile.write(selfSignedCert.getEncoded());
        caCertFile.close();
        FileOutputStream caPublicKeyFile = new FileOutputStream("caPublicKey.pem");
        caPublicKeyFile.write(selfSignedCert.getPublicKey().getEncoded());
        caPublicKeyFile.close();
    }

    public static void main(String[] args) throws CertificateException, NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException, IOException, InvalidKeySpecException {
        //CertificateAuthority ca = new CertificateAuthority();
        //createSelfSignedCert(ca);
        FileInputStream fl = new FileInputStream("caCert.crt");
        //FileInputStream keyFile = new FileInputStream("caPublicKey.pem");
        //PublicKey key = (PublicKey) PublicKeyFactory.createKey(keyFile);
        //createCertificate(fl, ca);
    }
}

