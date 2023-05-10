package ocsp;

import logic.OCSPClientLogic;
import model.CertificateAuthority;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.ocsp.ResponseData;
import org.bouncycastle.asn1.ocsp.SingleResponse;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import settings.OCSPClientSettings;

import java.io.*;
import java.net.ConnectException;
import java.net.Socket;
import java.net.SocketException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class OCSPClient {
    static int ocpsServerPort = 8888;
    static String serverHostName = "localhost";
    static String clientName;
    static String clientNamePath = "src/main/resources/client/ocsp/";
    static String certificatesPath = "../client/ocsp/certificates/";
    static String ocspClientPath = "../client/ocsp/";
    private static final DigestCalculatorProvider DIG_CALC_PROV;

    static {
        try {
            DIG_CALC_PROV = new JcaDigestCalculatorProviderBuilder().build();
        } catch (OperatorCreationException e) {
            throw new RuntimeException(e);
        }
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws IOException, ClassNotFoundException,
            NoSuchAlgorithmException, CertificateException {

        OCSPClientSettings.checkOCSPClientNameFile();

        X500Name ocspClientSubject = new X500Name("CN=" + clientName);
        CertificateAuthority ocspClientObj = new CertificateAuthority(clientName);
        PrivateKey ocspClientKey = ocspClientObj.getPrivateKey();

        OCSPClientSettings.checkStartConfigure(ocspClientObj, ocspClientKey, ocspClientSubject);

        FileInputStream fis = new FileInputStream(ocspClientPath + "client" + clientName + "Cert.crt");
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate ocspCertificate = (X509Certificate) cf.generateCertificate(fis);

        // запускаем подключение сокета по известным координатам и инициализируем приём сообщений с консоли клиента
        try (Socket socket = new Socket(serverHostName, ocpsServerPort);
             DataOutputStream oos = new DataOutputStream(socket.getOutputStream());
             DataInputStream ois = new DataInputStream(socket.getInputStream());) {

            System.out.println("Client connected to socket.\n");

            // проверяем живой ли канал и работаем если живой
            while (true) {

                File folder = new File(certificatesPath);
                File[] files = folder.listFiles();

                List<X509Certificate> certsToCheck = new ArrayList<>();

                for (File file : files) {
                    if (file.isFile() && file.getName().endsWith(".crt")) {
                        fis = new FileInputStream(file);
                        cf = CertificateFactory.getInstance("X.509");
                        X509Certificate cert = (X509Certificate) cf.generateCertificate(fis);
                        certsToCheck.add(cert);
                        fis.close();
                    }
                }
                X509CertificateHolder[] certificateHolders = new X509CertificateHolder[certsToCheck.size()];
                for (int i = 0; i < certsToCheck.size(); i++) {
                    certificateHolders[i] = new X509CertificateHolder(certsToCheck.get(i).getEncoded());
                }
                // формируем request
                OCSPReq ocspRequest =
                        OCSPClientLogic.makeOcspRequest(certsToCheck, clientName, DIG_CALC_PROV, ocspClientKey, certificateHolders);
                //String str = "sdskjhkjhbkbnd";
                // получить запрос в виде байтового потока
                byte[] ocspRequestByte = ocspRequest.getEncoded();
                //byte[] ocspRequestByte = str.getBytes();
                oos.writeInt(ocspRequestByte.length); // отправить длину байтового потока
                oos.write(ocspRequestByte); // отправить байтовый поток
                oos.flush(); // очистить поток

                // ждём чтобы сервер успел прочесть сообщение из сокета и ответить
                try {
                    // получить длину байтового потока с ответом OCSPResp
                    int responseLength = ois.readInt();
                    byte[] ocspResponse = new byte[responseLength];

                    int totalBytesRead = 0;
                    while (totalBytesRead < responseLength) {
                        int bytesRead = ois.read(ocspResponse, totalBytesRead, responseLength - totalBytesRead);
                        if (bytesRead == -1) {
                            throw new RuntimeException("End of stream reached before all data could be read");
                        }
                        totalBytesRead += bytesRead;
                    }
                    // считать ответ в буфер
                    OCSPResp ocspResp = new OCSPResp(OCSPResponse.getInstance(ocspResponse));
                    BasicOCSPResp basicResp = (BasicOCSPResp) ocspResp.getResponseObject();

                    ResponseData responseData = ResponseData.getInstance(basicResp.getTBSResponseData());
                    System.out.println("Response Version: " + basicResp.getVersion());
                    System.out.println("OCSPName: " + ois.readUTF());
                    System.out.println("producedAt: " + basicResp.getProducedAt());
                    switch (ocspResp.getStatus()) {
                        case 0 -> System.out.println("OCSPResponse status: \u001B[32mGOOD\u001B[0m");
                        case 1 -> System.out.println("OCSPResponse status: \u001B[31mMALFORMED REQUEST\u001B[0m");
                        case 2 -> System.out.println("OCSPResponse status: \u001B[31mINTERNAL ERROR\u001B[0m");
                        case 3 -> System.out.println("OCSPResponse status: \u001B[33mTRY LATER\u001B[0m");
                        case 5 -> System.out.println("OCSPResponse status: \u001B[33mSIG REQUIRED\u001B[0m");
                        case 6 -> System.out.println("OCSPResponse status: \u001B[31mUNAUTHORIZED\u001B[0m");
                        default -> System.out.println("OCSPResponse status: " + ocspResp.getStatus());
                    }

                    //System.out.println("OCSPResponse status: " + ocspResp.getStatus());
                    System.out.println("#-----------------------------------------------#");
                    for (ASN1Encodable responses : responseData.getResponses()) {
                        SingleResponse singleResponse = SingleResponse.getInstance(responses.toASN1Primitive());
                        System.out.println("Identification: " + singleResponse.getCertID().toASN1Primitive());
                        ASN1TaggedObject taggedStatus =
                                ASN1TaggedObject.getInstance(singleResponse.getCertStatus().toASN1Primitive());
                        switch (taggedStatus.getTagNo()) {
                            case 0 -> System.out.println("Certificate status: \u001B[32mGOOD\u001B[0m");
                            case 1 -> System.out.println("OCSPResponse status: \u001B[31mREVOKED\u001B[0m");
                            case 2 -> System.out.println("OCSPResponse status: \u001B[31mUNKNOWN\u001B[0m");
                        }

                        System.out.println("ThisUpdate: " + singleResponse.getThisUpdate().getDate());
                        if (singleResponse.getNextUpdate() == null) {
                            System.out.println("NextUpdate: " + singleResponse.getThisUpdate().getDate());
                        } else {
                            System.out.println("NextUpdate: " + singleResponse.getNextUpdate());
                        }
                        System.out.println("#-----------------------------------------------#");
                    }
                    System.out.println("ID of the EDS algorithm used: " + basicResp.getSignatureAlgOID());
                    System.out.println("EDS hash values of the response: " + Arrays.toString(basicResp.getSignature()));

                    //Thread.sleep(10000);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
            // на выходе из цикла общения закрываем свои ресурсы
        } catch (ConnectException e) {
            System.out.println("Sorry, connection problems. " +
                    "The server may not be available right now.");
        } catch (SocketException e) {
            System.out.println("The connection to the server is closed");
        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}

