package logic;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import settings.Settings;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Properties;

public class OCSPClientLogic extends Settings {
    /*public OCSPClientLogic() throws IOException {
        Properties prop = readPropertiesFile();

    }*/
    /**
     * Создание OCSP Request
     *
     * @param certsToCheck   Список сертификатов на проверку
     * @param ocspClientName Имя OCSP клиента
     * @param digCalcProv    интерфейс для вычисления хэш суммы
     * @return ocspRequest
     */
    public static OCSPReq makeOcspRequest(List<X509Certificate> certsToCheck, String ocspClientName,
                                          DigestCalculatorProvider digCalcProv, PrivateKey ocspClientKey,
                                          X509CertificateHolder[] chain) throws OperatorCreationException,
            OCSPException, CertificateEncodingException, IOException {
        readPropertiesFile();
        // basic request generation
        OCSPReqBuilder gen = new OCSPReqBuilder();
        if (ocspClientName != null && !ocspClientName.isEmpty()) {
            gen.setRequestorName(new GeneralName(GeneralName.directoryName, new X500Name("CN=" + ocspClientName)));
        }
        for (X509Certificate cert : certsToCheck) {
            // general id value for our test issuer cert and a serial number.
            CertificateID certId = new JcaCertificateID(
                    digCalcProv.get(CertificateID.HASH_SHA1), cert, cert.getSerialNumber());
            gen.addRequest(certId);
        }

        // create signer with private key and certificate chain
        JcaContentSignerBuilder builder = new JcaContentSignerBuilder("SHA256withRSA");
        ContentSigner signer = builder.build(ocspClientKey);
        // sign the request
        return gen.build(signer, chain);
    }
}
