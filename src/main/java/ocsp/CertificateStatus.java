//package ocsp;
//
//import org.bouncycastle.cert.ocsp.RevokedStatus;
//import org.bouncycastle.cert.ocsp.UnknownStatus;
//
//import javax.xml.crypto.Data;
//import java.util.Date;
//
//public interface CertificateStatus extends org.bouncycastle.cert.ocsp.CertificateStatus {
//    CertificateStatus GOOD = (CertificateStatus) org.bouncycastle.cert.ocsp.CertificateStatus.GOOD;
//    CertificateStatus REVOKED = (CertificateStatus) new RevokedStatus(new Date(),0);
//    CertificateStatus UNKNOWN = (CertificateStatus) new UnknownStatus();
//
//}
