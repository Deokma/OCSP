package ocsp;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.cert.ocsp.jcajce.JcaBasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.encoders.Base64;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Date;

public class OCSPClient {
    public static void main(String[] args) {
        try {
            // Чтение корневого сертификата из файла
            FileInputStream fis = new FileInputStream("caCert.crt");
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate caCert = (X509Certificate) cf.generateCertificate(fis);

            fis.close();

            // Чтение клиентского сертификата из файла
            fis = new FileInputStream("clientCert.crt");
            X509Certificate clientCert = (X509Certificate) cf.generateCertificate(fis);
            fis.close();
            // Проверка цепочки сертификатов
            clientCert.verify(caCert.getPublicKey());
            System.out.println("Цепочка сертификатов проверена успешно!");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static X509Certificate readCertificateFromFile(String filename) throws IOException, CertificateException {
        FileInputStream fis = new FileInputStream(filename);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(fis);
        fis.close();
        return cert;
    }


    private static PrivateKey readPrivateKeyFromFile(String filename) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        FileInputStream fis = new FileInputStream(filename);
        byte[] keyBytes = new byte[fis.available()];
        fis.read(keyBytes);
        fis.close();

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(Base64.decode(keyBytes));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    public static OCSPResp makeOcspResponse(
            X509Certificate caCert, PrivateKey caPrivateKey, OCSPReq ocspReq)
            throws OCSPException, OperatorCreationException, CertificateEncodingException {
        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().build();
        BasicOCSPRespBuilder respGen = new JcaBasicOCSPRespBuilder(
                caCert.getPublicKey(), digCalcProv.get(RespID.HASH_SHA1));
        CertificateID certID = ocspReq.getRequestList()[0].getCertID();
        // magic happens…
        respGen.addResponse(certID, CertificateStatus.GOOD);
        BasicOCSPResp resp = respGen.build(
                new JcaContentSignerBuilder("SHA384withECDSA").build(caPrivateKey),
                new X509CertificateHolder[]{new JcaX509CertificateHolder(caCert)},
                new Date());
        OCSPRespBuilder rGen = new OCSPRespBuilder();
        return rGen.build(OCSPRespBuilder.SUCCESSFUL, resp);
    }

    public static boolean isGoodCertificate(
            OCSPResp ocspResp, X509Certificate caCert, X509Certificate eeCert)
            throws OperatorCreationException, OCSPException, CertificateEncodingException {
        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().build();
        // SUCCESSFUL here means the OCSP request worked, it doesn't mean the certificate is valid.
        if (ocspResp.getStatus() == OCSPRespBuilder.SUCCESSFUL) {
            BasicOCSPResp resp = (BasicOCSPResp) ocspResp.getResponseObject();
            // make sure response is signed by the appropriate CA
            if (resp.isSignatureValid(new JcaContentVerifierProviderBuilder().build(caCert.getPublicKey()))) {
                // return the actual status of the certificate – null means valid.
                return resp.getResponses()[0].getCertID().matchesIssuer(
                        new JcaX509CertificateHolder(caCert), digCalcProv)
                        && resp.getResponses()[0].getCertID().getSerialNumber().equals(eeCert.getSerialNumber())
                        && resp.getResponses()[0].getCertStatus() == null;
            }
        }
        throw new IllegalStateException("OCSP Request Failed");
    }

    public static OCSPReq makeOcspRequest(X509Certificate caCert, X509Certificate certToCheck)
            throws OCSPException, OperatorCreationException, CertificateEncodingException {
        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().build();
        // general id value for our test issuer cert and a serial number.
        CertificateID certId = new JcaCertificateID(
                digCalcProv.get(CertificateID.HASH_SHA1), caCert, certToCheck.getSerialNumber());
        // basic request generation
        OCSPReqBuilder gen = new OCSPReqBuilder();
        gen.addRequest(certId);
        return gen.build();
    }

}