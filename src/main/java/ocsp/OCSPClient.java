package ocsp;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.ocsp.ResponseData;
import org.bouncycastle.asn1.ocsp.SingleResponse;
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
import java.util.List;
import java.util.Scanner;

public class OCSPClient {
    static int port = 8888;
    static String serverHostName = "localhost";
    static String clientName;
    static String clientNamePath = "src/main/resources/client/ocsp/";
    static String certificatesPath = "../client/ocsp/certificates/";
    private static final DigestCalculatorProvider DIG_CALC_PROV;

    static {
        try {
            DIG_CALC_PROV = new JcaDigestCalculatorProviderBuilder().build();
        } catch (OperatorCreationException e) {
            throw new RuntimeException(e);
        }
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws IOException, ClassNotFoundException {
        new File(clientNamePath).mkdirs();
        new File(certificatesPath).mkdirs();
        checkSubjNameFile();
        // запускаем подключение сокета по известным координатам и инициализируем приём сообщений с консоли клиента
        try (Socket socket = new Socket(serverHostName, port);
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
                        FileInputStream fis = new FileInputStream(file);
                        CertificateFactory cf = CertificateFactory.getInstance("X.509");
                        X509Certificate cert = (X509Certificate) cf.generateCertificate(fis);
                        certsToCheck.add(cert);
                        fis.close();
                    }
                }

                // добавить сертификаты в список certsToCheck
                OCSPReq ocspRequest = makeOcspRequest(certsToCheck, clientName, DIG_CALC_PROV); // получить запрос в виде байтового потока
                byte[] ocspRequestByte = ocspRequest.getEncoded();

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
                    System.out.println("OCSPResponse status: " + ocspResp.getStatus());
                    System.out.println("#-----------------------------------------------#");
                    for (ASN1Encodable responses : responseData.getResponses()) {
                        SingleResponse singleResponse = SingleResponse.getInstance(responses.toASN1Primitive());
                        System.out.println("Identification: " + singleResponse.getCertID());
                        ASN1TaggedObject taggedStatus = ASN1TaggedObject.getInstance(singleResponse.getCertStatus().toASN1Primitive());
                        if (taggedStatus.getTagNo() == 0) {
                            System.out.println("Status: GOOD");
                        }
                        if (taggedStatus.getTagNo() == 1) {
                            System.out.println("Status: REVOKED");
                        }
                        if (taggedStatus.getTagNo() == 2) {
                            System.out.println("Status: UNKNOWN");
                        }
                        System.out.println("ThisUpdate: " + singleResponse.getThisUpdate().getDate());
                        System.out.println("NextUpdate: " + singleResponse.getNextUpdate());
                        System.out.println("#-----------------------------------------------#");
                    }
                    //Thread.sleep(10000);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
            // на выходе из цикла общения закрываем свои ресурсы
        } catch (ConnectException e) {
            // TODO Auto-generated catch block
            System.out.println("Проблемы соединения с сервером");
        } catch (SocketException e) {

            System.out.println("\nХост разорвал соединение");
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Проверка на наличие файла с именем OCSPClient
     *
     * @throws IOException
     * @throws ClassNotFoundException
     */
    public static void checkSubjNameFile() throws IOException, ClassNotFoundException {
        if (!new File(clientNamePath + "clientName.dat").exists()) {
            Scanner scanner = new Scanner(System.in);
            System.out.print("Пожалуйста введите имя пользователя: ");
            clientName = scanner.nextLine();
            ObjectOutputStream subjectNameOut = new ObjectOutputStream(new FileOutputStream(clientNamePath + "clientName.dat"));
            subjectNameOut.writeObject(clientName);
            subjectNameOut.close();
        } else {
            ObjectInputStream subjectNameIn = new ObjectInputStream(new FileInputStream(clientNamePath + "clientName.dat"));
            clientName = (String) subjectNameIn.readObject();
        }
    }

    /**
     * Создание OCSP Request
     *
     * @param certsToCheck   Список сертификатов на проверку
     * @param ocspClientName Имя OCSP клиента
     * @param digCalcProv    интерфейс для вычисления хэш суммы
     * @return ocspRequest
     * @throws OperatorCreationException
     * @throws OCSPException
     * @throws CertificateEncodingException
     */
    public static OCSPReq makeOcspRequest(List<X509Certificate> certsToCheck, String ocspClientName, DigestCalculatorProvider digCalcProv) throws OperatorCreationException, OCSPException, CertificateEncodingException {
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
        return gen.build();
    }
}

