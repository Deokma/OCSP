package ocsp;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
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
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
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

    public static void main(String[] args) throws InterruptedException, IOException, ClassNotFoundException {

        checkSubjNameFile();
        // TODO первая версия валидности сертификата(Не по стандарту)
// ----------------------------------------------
//        try {
//            // Чтение корневого сертификата из файла
//            FileInputStream fis = new FileInputStream("src/main/resources/ca/server/caCert.crt");
//            CertificateFactory cf = CertificateFactory.getInstance("X.509");
//            X509Certificate caCert = (X509Certificate) cf.generateCertificate(fis);
//
//            fis.close();
//
//            // Чтение клиентского сертификата из файла
//            fis = new FileInputStream("src/main/resources/client/ocsp/certificates/clientЭтотклиентCert.crt");
//            X509Certificate clientCert = (X509Certificate) cf.generateCertificate(fis);
//            fis.close();
//            // Проверка цепочки сертификатов
//            clientCert.verify(caCert.getPublicKey());
//            System.out.println("Цепочка сертификатов проверена успешно!");
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//------------------------------------------
        // запускаем подключение сокета по известным координатам и нициализируем приём сообщений с консоли клиента
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

                OCSPReq ocspRequest = makeOcspRequest(certsToCheck, subjectName, DIG_CALC_PROV); // получить запрос в виде байтового потока
               /* CertificateID certID = ocspRequest.getRequestList()[0].getCertID();
                System.out.println(Arrays.hashCode(certID.getIssuerNameHash()));*/
                byte[] ocspRequestByte = ocspRequest.getEncoded();
                /*System.out.println(certID.getIssuerNameHash().hashCode());
                System.out.println(userCertificate.getIssuerX500Principal().getName().hashCode());
                System.out.println(caCert.getIssuerX500Principal().getName().hashCode());
                System.out.println(Arrays.equals(certID.getIssuerNameHash(), caCert.getIssuerX500Principal().getName().getBytes()));
*/
                oos.writeInt(ocspRequestByte.length); // отправить длину байтового потока
                oos.write(ocspRequestByte); // отправить байтовый поток
                oos.flush(); // очистить поток


//                System.out.println("Сертификаты были отправлены.");
                //System.out.println("Clien sent message " + clientCommand + " to server.");
                // Thread.sleep(1000);
                // ждём чтобы сервер успел прочесть сообщение из сокета и ответить
                try {
                    // получить длину байтового потока с ответом
                    int responseLength = ois.readInt();
                    //byte[] ocspresp = ois.readAllBytes();
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
                    //ois.readFully(ocspResponse);
                    // создать объект OCSPResponse из буфера с ответом
                    // OCSPResponse response = OCSPResponse.getInstance(ocspResponse);
                    BasicOCSPResp basicResp = new BasicOCSPResp(BasicOCSPResponse.getInstance(ocspResponse));

                    // Печать значений

                    ResponseData responseData = ResponseData.getInstance(basicResp.getTBSResponseData());

                    System.out.println("Response Version: " + basicResp.getVersion());
                    System.out.println("OCSPName: " + ois.readUTF());
                    //System.out.println("ResponseData: " + responseData.getResponses().toString());
                    System.out.println("producedAt: " + basicResp.getProducedAt());
                    //System.out.println("  responderId: " + responseData.getResponderID().toString());
                    //System.out.println("  responses:" + responseData.getResponses());
                    for (ASN1Encodable responses : responseData.getResponses()) {
                        SingleResponse singleResponse = SingleResponse.getInstance(responses.toASN1Primitive());
                        System.out.println("Identification: " + singleResponse.getCertID());
                        System.out.println("Status: " + singleResponse.getCertStatus().getStatus());
                        System.out.println("Validity request period from: " + singleResponse.getThisUpdate().getDate());
                        System.out.println("To: " + singleResponse.getNextUpdate());
                        //System.out.println(singleResponse.getNextUpdate().toString());
                        //System.out.println("    certId: " + ( responses).toString());
                        System.out.println();
//                        System.out.println("    certStatus: " + ((SingleResponse) responses).getCertStatus());
//                        System.out.println("    thisUpdate: " + ((SingleResponse) responses).getThisUpdate());
//                        System.out.println("    nextUpdate: " + ((SingleResponse) responses).getNextUpdate());
                    }

//                    // обработать ответ
//                    if (response.getResponseStatus().getIntValue() == OCSPResponseStatus.SUCCESSFUL) {
//                        // успешный ответ, получить и обработать ответные данные
//                        System.out.println("Всё отлично");
//                        // BasicOCSPResp basicResp = (BasicOCSPResp) response.getResponseObject();
//                        // ...
//                    } else {
//                        // ответ содержит ошибку, обработать ее
//                        // ...
//                        System.out.println("Ничего не отлично");
//                    }
                    //System.out.println(response.getResponseStatus().getIntValue());
                    // если условие разъединения не достигнуто продолжаем работу
                    //System.out.println("Client sent message & start waiting for data from server...");
                    Thread.sleep(10000);

                    // проверяем, что нам ответит сервер на сообщение(за предоставленное ему время в паузе он должен был успеть ответить)
                    if (ois.read() > -1) {

                        // если успел забираем ответ из канала сервера в сокете и сохраняем её в ois переменную,  печатаем на свою клиентскую консоль
                        System.out.println("reading...");
                        String in = ois.readUTF();
                        System.out.println(in);
                    }
                } catch (IOException | InterruptedException e) {
                    throw new RuntimeException(e);
                }
            }
            // на выходе из цикла общения закрываем свои ресурсы
        } catch (ConnectException e) {
            // TODO Auto-generated catch block
            System.out.println("Проблемы соединения с сервером");
            //e.printStackTrace();
        } catch (SocketException e) {

            System.out.println("Программа на хост-компьютере разорвала установленное подключение");
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
            System.out.print("Пожалуйства введите имя пользователя: ");
            subjectName = scanner.nextLine();
            ObjectOutputStream subjectNameOut = new ObjectOutputStream(new FileOutputStream(subjectNamePath));
            subjectNameOut.writeObject(subjectName);
            subjectNameOut.close();
        } else {
            ObjectInputStream subjectNameIn = new ObjectInputStream(new FileInputStream(subjectNamePath));
            subjectName = (String) subjectNameIn.readObject();
        }
    }

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

