package logic;

import connect.DBManager;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.cert.ocsp.jcajce.JcaBasicOCSPRespBuilder;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import settings.Settings;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.*;

public class OCSPServerLogic extends Settings {
    static DBManager db = new DBManager();
static boolean serverIsWork;

   /* public OCSPServerLogic() throws IOException {
        Properties prop = readPropertiesFile();
        serverIsWork = Boolean.parseBoolean(prop.getProperty("ocspServerWorking"));
    }*/

    public static OCSPResp makeOcspResponse(
            X509Certificate ocspCert, PrivateKey ocpsPrivateKey, OCSPReq ocspReq)
            throws OCSPException, OperatorCreationException, CertificateEncodingException, IOException {
        readPropertiesFile();
        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().build();
        BasicOCSPRespBuilder respGen = new JcaBasicOCSPRespBuilder(
                ocspCert.getPublicKey(), digCalcProv.get(RespID.HASH_SHA1));
        try {
            respGen.setResponseExtensions(new Extensions(new Extension(
                    OCSPObjectIdentifiers.id_pkix_ocsp_basic, false, new DEROctetString(new byte[0]))));
            // TODO нужно углублённо разобраться с идентификаторами
            // Check if the RequestList is not empty
            if (ocspReq.getRequestList() == null || ocspReq.getRequestList().length == 0) {
                respGen.setResponseExtensions(new Extensions(new Extension(
                        OCSPObjectIdentifiers.id_pkix_ocsp_basic, false, new DEROctetString(new byte[0]))));
                BasicOCSPResp resp = respGen.build(
                        new JcaContentSignerBuilder("SHA384withRSA").build(ocpsPrivateKey),
                        new X509CertificateHolder[]{new JcaX509CertificateHolder(ocspCert)},
                        new Date());
                OCSPRespBuilder rGen = new OCSPRespBuilder();
                return rGen.build(OCSPRespBuilder.MALFORMED_REQUEST, resp);
            }
            if (!ocspReq.isSigned()) {
                respGen.setResponseExtensions(new Extensions(new Extension(
                        OCSPObjectIdentifiers.id_pkix_ocsp_basic, false, new DEROctetString(new byte[0]))));
                BasicOCSPResp resp = respGen.build(
                        new JcaContentSignerBuilder("SHA384withRSA").build(ocpsPrivateKey),
                        new X509CertificateHolder[]{new JcaX509CertificateHolder(ocspCert)},
                        new Date());
                OCSPRespBuilder rGen = new OCSPRespBuilder();
                return rGen.build(OCSPRespBuilder.SIG_REQUIRED, resp);
            }
            // проверить подпись и подлинность запроса
            if (!ocspReq.isSignatureValid(new JcaContentVerifierProviderBuilder().build(ocspCert.getPublicKey()))) {
                respGen.setResponseExtensions(new Extensions(new Extension(
                        OCSPObjectIdentifiers.id_pkix_ocsp_basic, false, new DEROctetString(new byte[0]))));
                BasicOCSPResp resp = respGen.build(
                        new JcaContentSignerBuilder("SHA384withRSA").build(ocpsPrivateKey),
                        new X509CertificateHolder[]{new JcaX509CertificateHolder(ocspCert)},
                        new Date());
                OCSPRespBuilder rGen = new OCSPRespBuilder();
                return rGen.build(OCSPRespBuilder.UNAUTHORIZED, resp);
            }
            if (!serverIsWork) {
                respGen.setResponseExtensions(new Extensions(new Extension(
                        OCSPObjectIdentifiers.id_pkix_ocsp_basic, false, new DEROctetString(new byte[0]))));
                BasicOCSPResp resp = respGen.build(
                        new JcaContentSignerBuilder("SHA384withRSA").build(ocpsPrivateKey),
                        new X509CertificateHolder[]{new JcaX509CertificateHolder(ocspCert)},
                        new Date());
                OCSPRespBuilder rGen = new OCSPRespBuilder();
                return rGen.build(OCSPRespBuilder.TRY_LATER, resp);
            }

            // Process each request in the RequestList
            List<CertificateID> certificateIDList = new ArrayList<>();
            for (Req request : ocspReq.getRequestList()) {
                certificateIDList.add(request.getCertID());
            }
            for (CertificateID certID : certificateIDList) {
                if (db.certExist(certID)) {
                    if (db.getCertStatusByCertId(certID) != null) {
                        if (Objects.equals(db.getCertStatusByCertId(certID), "GOOD"))
                            respGen.addResponse(certID, CertificateStatus.GOOD);
                        if (Objects.equals(db.getCertStatusByCertId(certID), "REVOKED"))
                            respGen.addResponse(certID, new RevokedStatus(new Date(), 0));
                    } else respGen.addResponse(certID, new UnknownStatus());
                } else respGen.addResponse(certID, new UnknownStatus());
            }
            BasicOCSPResp resp = respGen.build(
                    new JcaContentSignerBuilder("SHA384withRSA").build(ocpsPrivateKey),
                    new X509CertificateHolder[]{new JcaX509CertificateHolder(ocspCert)},
                    new Date());
            OCSPRespBuilder rGen = new OCSPRespBuilder();
            return rGen.build(OCSPRespBuilder.SUCCESSFUL, resp);
        } catch (Exception e) {
            respGen.setResponseExtensions(new Extensions(new Extension(
                    OCSPObjectIdentifiers.id_pkix_ocsp_basic, false, new DEROctetString(new byte[0]))));
            BasicOCSPResp resp = respGen.build(
                    new JcaContentSignerBuilder("SHA384withRSA").build(ocpsPrivateKey),
                    new X509CertificateHolder[]{new JcaX509CertificateHolder(ocspCert)},
                    new Date());
            OCSPRespBuilder rGen = new OCSPRespBuilder();
            return rGen.build(OCSPRespBuilder.INTERNAL_ERROR, resp);
        }
    }
}
