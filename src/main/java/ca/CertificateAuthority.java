package ca;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

public class CertificateAuthority implements Serializable {
    private KeyPair keyPair;
    private final X500Name issuer;
    private BigInteger serialNumber;

    public CertificateAuthority(String caName) throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048, new SecureRandom());
        String caNameToX500 = "CN=" + caName;
        this.keyPair = keyPairGenerator.generateKeyPair();
        this.issuer = new X500Name("CN=" + caName);
        this.serialNumber = BigInteger.ONE;
    }

    public X509Certificate issueCertificate(PublicKey publicKey, Date startDate, Date endDate, String clientName) throws OperatorCreationException, CertificateException, CertIOException {
        X500Name subject = new X500Name("CN=" + clientName);
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(issuer, serialNumber, startDate, endDate, subject, publicKey);
        // Add extensions
        certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        certBuilder.addExtension(Extension.subjectKeyIdentifier, false, new SubjectKeyIdentifier(publicKey.getEncoded()));

        // Sign the certificate
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(keyPair.getPrivate());
        X509CertificateHolder certHolder = certBuilder.build(signer);
        X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(certHolder);

        // Increment serial number for next certificate
        serialNumber = serialNumber.add(BigInteger.ONE);

        return certificate;
    }

    public void savePrivateKey(String fileName) throws IOException {
        byte[] privateKeyBytes = keyPair.getPrivate().getEncoded();
        FileOutputStream outputStream = new FileOutputStream(fileName);
        outputStream.write(privateKeyBytes);
        outputStream.close();
    }

    public void loadPrivateKey(PrivateKey privateKey) {
        this.keyPair = new KeyPair(getPublicKey(), privateKey);
    }


    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }

    public PrivateKey getPrivateKey() {
        return keyPair.getPrivate();
    }


    public X509Certificate createSelfSignedCertificate(Date startDate, Date endDate) throws OperatorCreationException, CertificateException, CertIOException {
        //X500Name subject = new X500Name("CN=ca");
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(issuer, serialNumber, startDate, endDate, issuer, keyPair.getPublic());
        //X509v1CertificateBuilder certBuilder1 = new JcaX509v1CertificateBuilder(issuer, serialNumber, startDate, endDate, issuer, keyPair.getPublic());
        // Add extensions
        certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign));
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
        certBuilder.addExtension(Extension.subjectKeyIdentifier, false, new SubjectKeyIdentifier(keyPair.getPublic().getEncoded()));
        // Sign the certificate
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(keyPair.getPrivate());
        X509CertificateHolder certHolder = certBuilder.build(signer);
        X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(certHolder);

        // Increment serial number for next certificate
        serialNumber = serialNumber.add(BigInteger.ONE);

        return certificate;
    }

    public X500Name getIssuer() {
        return issuer;
    }
}