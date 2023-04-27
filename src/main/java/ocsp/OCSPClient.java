package ocsp;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ocsp.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.io.*;
import java.net.ConnectException;
import java.net.Socket;
import java.net.SocketException;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;

public class OCSPClient {
    static String subjectName;
    static String subjectNamePath = "src/main/resources/client/ocsp/subjectName.dat";
    static String subjectPath = "src/main/resources/client/ocsp/";
    static String certificatesPath = "src/main/resources/client/ocsp/certificates/";
    static String keysPath = "src/main/resources/client/ca/";
    private static final DigestCalculatorProvider DIG_CALC_PROV;
    static String caCertPath = "src/main/resources/ca/server/caCert.crt";

    static {
        try {
            DIG_CALC_PROV = new JcaDigestCalculatorProviderBuilder().build();
        } catch (OperatorCreationException e) {
            throw new RuntimeException(e);
        }
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws IOException, ClassNotFoundException {

        checkSubjNameFile();
        // запускаем подключение сокета по известным координатам и инициализируем приём сообщений с консоли клиента
        try (Socket socket = new Socket("localhost", 8888);
             // BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
             DataOutputStream oos = new DataOutputStream(socket.getOutputStream());
             DataInputStream ois = new DataInputStream(socket.getInputStream());) {

            System.out.println("Client connected to socket.\n");

            // проверяем живой ли канал и работаем если живой
            while (true) {

                Thread.sleep(1000);

                FileInputStream fis = new FileInputStream(certificatesPath + "clientЭтот клиентCert.crt");
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509Certificate userCertificate = (X509Certificate) cf.generateCertificate(fis);
                fis = new FileInputStream(certificatesPath + "clientЭтот OCSPCert.crt");
                X509Certificate userCertificate1 = (X509Certificate) cf.generateCertificate(fis);
                fis = new FileInputStream(caCertPath);
                X509Certificate caCert = (X509Certificate) cf.generateCertificate(fis);
                List<X509Certificate> certsToCheck = new ArrayList<>();
                certsToCheck.add(userCertificate);
                certsToCheck.add(userCertificate1);

                // добавить сертификаты в список certsToCheck
                OCSPReq ocspRequest = makeOcspRequest(caCert, certsToCheck, subjectName, DIG_CALC_PROV); // получить запрос в виде байтового потока
                byte[] ocspRequestByte = ocspRequest.getEncoded();

                oos.writeInt(ocspRequestByte.length); // отправить длину байтового потока
                oos.write(ocspRequestByte); // отправить байтовый поток
                oos.flush(); // очистить поток

                // ждём чтобы сервер успел прочесть сообщение из сокета и ответить
                try {
                    // получить длину байтового потока с ответом BasicOCSPResp
                    int basicResponseLength = ois.readInt();
                    byte[] basicOcspResponse = new byte[basicResponseLength];


                    int totalBasicBytesRead = 0;
                    while (totalBasicBytesRead < basicResponseLength) {
                        int basicBytesRead = ois.read(basicOcspResponse, totalBasicBytesRead, basicResponseLength - totalBasicBytesRead);
                        if (basicBytesRead == -1) {
                            throw new RuntimeException("End of stream reached before all data could be read");
                        }
                        totalBasicBytesRead += basicBytesRead;
                    }
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
                    BasicOCSPResp basicResp = new BasicOCSPResp(BasicOCSPResponse.getInstance(basicOcspResponse));
                    OCSPResp ocspResp = new OCSPResp(OCSPResponse.getInstance(ocspResponse));
                    // Печать значений

                    String certificateStatus = OCSPUtils.getCertificateStatus(ocspResp);

                    ResponseData responseData = ResponseData.getInstance(basicResp.getTBSResponseData());
                    System.out.println("#-----------------------------------------------#");
                    System.out.println("Response Version: " + basicResp.getVersion());
                    System.out.println("OCSPName: " + ois.readUTF());
                    System.out.println("producedAt: " + basicResp.getProducedAt());
                    for (ASN1Encodable responses : responseData.getResponses()) {
                        SingleResponse singleResponse = SingleResponse.getInstance(responses.toASN1Primitive());
                        System.out.println("Identification: " + singleResponse.getCertID().toASN1Primitive());
                        System.out.println("Status: \u001B[32m" + certificateStatus + "\u001B[0m");
                        System.out.println("ThisUpdate: " + singleResponse.getThisUpdate().getDate());
                        System.out.println("NextUpdate: " + singleResponse.getNextUpdate());
                    }
                    System.out.println("#-----------------------------------------------#");
                    //Thread.sleep(10000);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
            // на выходе из цикла общения закрываем свои ресурсы
        } catch (ConnectException e) {
            // TODO Auto-generated catch block
            System.out.println("Проблемы соединения с сервером");
            //e.printStackTrace();
        } catch (SocketException e) {

            System.out.println("\nХост разорвал соединение");
            //e.printStackTrace();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void checkSubjNameFile() throws IOException, ClassNotFoundException {
        if (!new File(subjectNamePath).exists()) {
            Scanner scanner = new Scanner(System.in);
            System.out.print("Пожалуйста введите имя пользователя: ");
            subjectName = scanner.nextLine();
            ObjectOutputStream subjectNameOut = new ObjectOutputStream(new FileOutputStream(subjectNamePath));
            subjectNameOut.writeObject(subjectName);
            subjectNameOut.close();
        } else {
            ObjectInputStream subjectNameIn = new ObjectInputStream(new FileInputStream(subjectNamePath));
            subjectName = (String) subjectNameIn.readObject();
        }
    }

    public static OCSPReq makeOcspRequest(X509Certificate caCert, List<X509Certificate> certsToCheck, String ocspClientName, DigestCalculatorProvider digCalcProv) throws OperatorCreationException, OCSPException, CertificateEncodingException {
        // basic request generation
        OCSPReqBuilder gen = new OCSPReqBuilder();
        if (ocspClientName != null && !ocspClientName.isEmpty()) {
            gen.setRequestorName(new GeneralName(GeneralName.directoryName, new X500Name("CN=" + ocspClientName)));
        }
        for (X509Certificate cert : certsToCheck) {
            // general id value for our test issuer cert and a serial number.
            CertificateID certId = new JcaCertificateID(
                    digCalcProv.get(CertificateID.HASH_SHA1), caCert, cert.getSerialNumber());
            gen.addRequest(certId);
        }
        return gen.build();
    }
}

