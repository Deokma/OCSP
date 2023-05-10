package logic;

import model.CertificateAuthority;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import settings.Settings;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Properties;

public class CAServerLogic extends Settings {
    static String caCertificatesPath;
    static String caServerKeysPath;

    public CAServerLogic() throws IOException {
        //Properties prop = readPropertiesFile();
      //  caCertificatesPath = prop.getProperty("caCertificatesPath");
       // caServerKeysPath = prop.getProperty("caServerKeysPath");
    }

    /**
     * Создание сертификата
     *
     * @param ca              объект УЦ
     * @param certificateName имя для сертификата
     * @param publicKey       сгенерированный публичный ключ
     * @return имя сертификата
     */
    public static String createCertificate(CertificateAuthority ca, String certificateName, PublicKey publicKey) throws
            CertificateException, OperatorCreationException, IOException {
        readPropertiesFile();
        String subjName = certificateName.substring(3);

        // Выдача сертификата клиенту
        //ca.savePrivateKey(caKeysPath + "client" + subjName + "PrivateKey.pem");

        X509Certificate clientCert = ca.issueCertificate(publicKey, new Date(),
                new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000L), subjName);

        String certFileName = "client" + subjName + "Cert.crt";
        String privateKeyFileName = "client" + subjName + "PrivateKey.pem";

        // Check if files already exist, if so add a numeric value to the file name
        int fileNumber = 0;
        while (new File(caCertificatesPath + certFileName).exists()) {
            fileNumber++;
            certFileName = "client" + subjName + "Cert" + fileNumber + ".crt";
        }
        fileNumber = 0;
        while (new File(caServerKeysPath + privateKeyFileName).exists()) {
            fileNumber++;
            privateKeyFileName = "client" + subjName + "PrivateKey" + fileNumber + ".pem";
        }

        // Save certificate and private key to files
        FileOutputStream fos = new FileOutputStream(caCertificatesPath + certFileName);
        fos.write(clientCert.getEncoded());
        fos.close();

        fos = new FileOutputStream(caServerKeysPath + privateKeyFileName);
        fos.write(ca.getPrivateKey().getEncoded());
        fos.close();

        return certFileName;
    }
    /**
     * Запрос на обработку сертификата для клиента
     *
     * @param ca  объект УЦ
     * @param csr запрос на обработку сертификата
     */
    public static String handleRequest(CertificateAuthority ca, PKCS10CertificationRequest csr) throws
            CertificateException, NoSuchAlgorithmException, IOException,
            NoSuchProviderException, OperatorCreationException {
        // Обработка запроса клиента
        SubjectPublicKeyInfo publicKeyInfo = csr.getSubjectPublicKeyInfo();

        // Create a PublicKey object from the SubjectPublicKeyInfo
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(new BouncyCastleProvider());
        PublicKey publicKey = converter.getPublicKey(publicKeyInfo);
        String cert = CAServerLogic.createCertificate(ca, csr.getSubject().toString(), publicKey);
        System.out.println("Certificate created: " + cert.toString());
        return cert;
    }
}
