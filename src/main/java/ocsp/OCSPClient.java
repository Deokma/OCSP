package ocsp;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.ocsp.OCSPRequest;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.ocsp.TBSRequest;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.io.*;
import java.net.ConnectException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Scanner;

public class OCSPClient {
    static String subjectName;
    static String subjectNamePath = "src/main/resources/client/ocsp/subjectName.dat";
    static String subjectPath = "src/main/resources/client/ocsp/";
    static String certificatesPath = "src/main/resources/client/ocsp/certificates/";

    public static void main(String[] args) throws InterruptedException, IOException, ClassNotFoundException {

        checkSubjNameFile();
        // Вот это нужно
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
//            fis = new FileInputStream("../clientDenisCert.crt");
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

            System.out.println("Client connected to socket.");
            System.out.println();
            System.out.println("Client writing channel = oos & reading channel = ois initialized.");

            // проверяем живой ли канал и работаем если живой
            while (true) {
                // ждём консоли клиента на предмет появления в ней данных

                // данные появились - работаем
                System.out.println("Client start writing in channel...");
                Thread.sleep(1000);
                // String clientCommand = br.readLine();

                // Подготовить список сертификатов, которые нужно проверить
                //List<X509Certificate> certificates = null;

                // Получаем сертификаты из файлов
//                List<X509Certificate> certificates = new ArrayList<>();
//                File folder = new File(certificatesPath);
//                if (folder.isDirectory()) {
//                    for (File file : Objects.requireNonNull(folder.listFiles((dir, name) -> name.endsWith(".crt")))) {
//                        if (file.isFile()) {
//                            try (InputStream is = new FileInputStream(file)) {
//                                CertificateFactory cf = CertificateFactory.getInstance("X.509");
//                                X509Certificate cert = (X509Certificate) cf.generateCertificate(is);
//                                certificates.add(cert);
//                            } catch (Exception e) {
//                                e.getMessage();
//                            }
//                        }
//                    }
//                }
//
//                // Создать последовательность идентификаторов сертификатов
//                ASN1EncodableVector certList = new ASN1EncodableVector();
//                for (X509Certificate cert : certificates) {
//                    try {
//                        X509CertificateHolder holder = new JcaX509CertificateHolder(cert);
//                        certList.add(holder.toASN1Structure());
//                    } catch (CertificateEncodingException e) {
//                        e.printStackTrace();
//                    }
//                }
//
//                ASN1Sequence certSequence = new DERSequence(certList);
//
//                // Создать объект TBSRequest
//                GeneralName requestorName = new GeneralName(GeneralName.dNSName, subjectName); // имя клиента
//                Extensions extensions = null; // дополнительные расширения
//                TBSRequest tbsRequest = new TBSRequest(requestorName, certSequence, extensions);
//                // Создать объект OCSPRequest
//                OCSPRequest request = new OCSPRequest(tbsRequest, null); // подпись может быть null
                FileInputStream fis = new FileInputStream(new File(certificatesPath + "clientЭтотклиентCert.crt"));
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509Certificate userCertificate = (X509Certificate) cf.generateCertificate(fis);
                byte[] ocspRequest = makeOcspRequest(userCertificate).getEncoded(); // получить запрос в виде байтового потока
                oos.writeInt(ocspRequest.length); // отправить длину байтового потока
                oos.write(ocspRequest); // отправить байтовый поток
                oos.flush(); // очистить поток


//                System.out.println("Сертификаты были отправлены.");
                //System.out.println("Clien sent message " + clientCommand + " to server.");
                // Thread.sleep(1000);
                // ждём чтобы сервер успел прочесть сообщение из сокета и ответить
                try {
                    // получить длину байтового потока с ответом
                    int responseLength = ois.readInt();
                    // создать буфер для ответа
                    byte[] ocspResponse = new byte[ois.readInt()];
                    if (ocspResponse.length > 0) {
                        ois.readFully(ocspResponse, 0, ocspResponse.length);
                    } else {
                        throw new RuntimeException("OCSP response length is 0");
                    }

                    // считать ответ в буфер
                    ois.readFully(ocspResponse);
                    // создать объект OCSPResponse из буфера с ответом
                    OCSPResponse response = OCSPResponse.getInstance(ocspResponse);

                    // обработать ответ
                    if (response.getResponseStatus().getIntValue() == OCSPResponseStatus.SUCCESSFUL) {
                        // успешный ответ, получить и обработать ответные данные
                        System.out.println("Всё отлично");
                        // BasicOCSPResp basicResp = (BasicOCSPResp) response.getResponseObject();
                        // ...
                    } else {
                        // ответ содержит ошибку, обработать ее
                        // ...
                        System.out.println("Ничего не отлично");
                    }
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
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (OCSPException e) {
            throw new RuntimeException(e);
        } catch (CertificateEncodingException e) {
            throw new RuntimeException(e);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        } catch (OperatorCreationException e) {
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

    public static OCSPReq makeOcspRequest(X509Certificate certToCheck) throws OperatorCreationException, OCSPException, CertificateEncodingException {
        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder()
                .setProvider("BCFIPS").build();
        // general id value for our test issuer cert and a serial number.
        CertificateID certId = new JcaCertificateID(
                digCalcProv.get(CertificateID.HASH_SHA1), certToCheck, certToCheck.getSerialNumber());
        // basic request generation
        OCSPReqBuilder gen = new OCSPReqBuilder();
        gen.addRequest(certId);
        return gen.build();
    }

}

