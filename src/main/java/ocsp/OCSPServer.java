package ocsp;

import ca.CertificateAuthority;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.cert.ocsp.jcajce.JcaBasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.*;
import java.math.BigInteger;
import java.net.ConnectException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Date;
import java.util.Scanner;

/**
 * OCSP сервер
 */
public class OCSPServer {
    private static final DigestCalculatorProvider DIG_CALC_PROV;

    static {
        try {
            DIG_CALC_PROV = new JcaDigestCalculatorProviderBuilder().build();
        } catch (OperatorCreationException e) {
            throw new RuntimeException(e);
        }
        Security.addProvider(new BouncyCastleProvider());
    }

    static int port = 8888;
    static int caPort = 9999;
    static String ocspServerPath = "src/main/resources/ocsp/server/";
    static String caCertPath = "src/main/resources/ca/server/caCert.crt";
    static String ocspName;
    static String serverHostName = "localhost";

    public static void main(String[] args) throws IOException, ClassNotFoundException, NoSuchAlgorithmException, NoSuchProviderException, CertificateException, InvalidKeySpecException {

        checkOCSPNameFile();
        X500Name ocspSubject = new X500Name("CN=" + ocspName);
        FileInputStream fis = new FileInputStream("src/main/resources/ocsp/server/clientЭтот OCSPCert.crt");
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate ocspCertificate = (X509Certificate) cf.generateCertificate(fis);

        fis = new FileInputStream(caCertPath);

        X509Certificate caCert = (X509Certificate) cf.generateCertificate(fis);

        CertificateAuthority ocspObj = new CertificateAuthority(ocspName);
        PrivateKey ocspKey = ocspObj.getPrivateKey();

        checkStartConfigure(ocspObj, ocspKey, ocspSubject);

        File filePrivateKey = new File(ocspServerPath + "privateKey.key");
        byte[] encodedPrivateKey = Files.readAllBytes(filePrivateKey.toPath());

        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey ocspPrivateKey = keyFactory.generatePrivate(privateKeySpec);


        ServerSocket serverSocket = new ServerSocket(port);
        System.out.println("Сервер запущен на порту " + port);

        while (true) {
            Socket clientSocket = serverSocket.accept(); // Ждем подключения клиента
            System.out.println("#-----------------------------------------------#");
            System.out.println("Подключился клиент " + clientSocket.getInetAddress());

            // канал записи в сокет
            DataOutputStream oos = new DataOutputStream(clientSocket.getOutputStream());
            //System.out.println("DataOutputStream created");

            // канал чтения из сокета
            DataInputStream ois = new DataInputStream(clientSocket.getInputStream());
            //System.out.println("DataInputStream created");

            new Thread(() -> {
                try {
                    // получить длину байтового потока с запросом
                    int ocspRequestLength = ois.readInt();
                    // создать буфер для запроса
                    byte[] ocspRequest = new byte[ocspRequestLength];
                    // считать запрос в буфер
                    ois.readFully(ocspRequest);
                    // создать объект OCSPRequest из буфера с запросом
                    OCSPReq ocspReq = new OCSPReq(ocspRequest);

                    CertificateID certID = ocspReq.getRequestList()[0].getCertID();
                    CertificateID certID1 = ocspReq.getRequestList()[1].getCertID();
                    // TODO доработать получения списка certID, а не одного

                    byte[] hash = certID.getIssuerNameHash();
                    byte[] key = certID.getIssuerKeyHash();

                    CertificateID caCertID = new JcaCertificateID(
                            DIG_CALC_PROV.get(CertificateID.HASH_SHA1), caCert, caCert.getSerialNumber());

                    BigInteger serialNumber = certID.getSerialNumber();
                    PublicKey publicKey = caCert.getPublicKey();
                    JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
                    ResponderID responderID = new ResponderID(ASN1OctetString.getInstance(extUtils.createSubjectKeyIdentifier(publicKey)));

                    RespID respID = new RespID(ResponderID.getInstance(responderID.toASN1Primitive()));
                    BasicOCSPRespBuilder builder = new BasicOCSPRespBuilder(respID);

                    if (Arrays.equals(caCertID.getIssuerNameHash(), hash)
                            && Arrays.equals(caCertID.getIssuerKeyHash(), key)) {
                        CertificateStatus certStatus = getCertificateStatus();
                        builder.addResponse(certID, certStatus);
                    } else {
//                         TODO сделать отправку сообщения "Неверный сертификат", при несовпадении
//                          IssuerName и IssuerKey.
                    }

                    ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSA").build(ocspKey);
                    BasicOCSPResp basicOCSPResp = builder.build(contentSigner, null, new Date());
                    OCSPResp ocspResp = makeOcspResponse(caCert, ocspPrivateKey, ocspReq);
                    System.out.println("Имя отправителя:" + ocspReq.getRequestorName().getName());
                    System.out.println("Количество запросов: " + ocspReq.getRequestList().length);
                    //TODO нужно доработать обработку сертификатов (Лист)
                    System.out.println("Статус сертификата: \u001B[32m" + OCSPUtils.getCertificateStatus(ocspResp) + "\u001B[0m");
                    // отправка ответа клиенту
                    byte[] ocspBasicResponseBytes = basicOCSPResp.getEncoded();
                    byte[] ocspResponseBytes = ocspResp.getEncoded();
                    oos.writeInt(ocspBasicResponseBytes.length);
                    oos.write(ocspBasicResponseBytes);
                    oos.writeInt(ocspResponseBytes.length);
                    oos.write(ocspResponseBytes);
                    oos.writeUTF(ocspName);
                    oos.flush();

                    // clientSocket.setSoTimeout(10000);
                } catch (IOException e) {
                    e.printStackTrace();
                } catch (Exception e) {
                    throw new RuntimeException(e);
                } finally {
                    try {
                        // Закрываем соединение с клиентом
                        clientSocket.close();
                        System.out.println("Соединение с клиентом " + clientSocket.getInetAddress() + " закрыто");
                        System.out.println("#-----------------------------------------------#");
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }).start();
        }
    }

    public static OCSPResp makeOcspResponse(
            X509Certificate caCert, PrivateKey ocpsPrivateKey, OCSPReq ocspReq)
            throws OCSPException, OperatorCreationException, CertificateEncodingException {
        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().build();
        BasicOCSPRespBuilder respGen = new JcaBasicOCSPRespBuilder(
                caCert.getPublicKey(), digCalcProv.get(RespID.HASH_SHA1));
        CertificateID certID = ocspReq.getRequestList()[0].getCertID();
        // TODO тут нужно доработать получение статуса
        // magic happens…
        respGen.addResponse(certID, CertificateStatus.GOOD);
        BasicOCSPResp resp = respGen.build(
                new JcaContentSignerBuilder("SHA384withRSA").build(ocpsPrivateKey),
                new X509CertificateHolder[]{new JcaX509CertificateHolder(caCert)},
                new Date());
        OCSPRespBuilder rGen = new OCSPRespBuilder();
        return rGen.build(OCSPRespBuilder.SUCCESSFUL, resp);
    }

    private static CertificateStatus getCertificateStatus() {
        // TODO нужно доработать метод
        // Check the certificate status
        // return new RevokedStatus(new Date(), 0);  // set the certificate status as revoked
        return CertificateStatus.GOOD;  // set the certificate status as good
        //return new UnknownStatus();  // set the certificate status as unknown
    }

    // Метод для обработки OCSP запросов

    public static void checkOCSPNameFile() throws IOException, ClassNotFoundException {
        if (!new File(ocspServerPath + "ocspName.dat").exists()) {
            System.out.print("Задайте название вашего OCSP: ");
            Scanner in = new Scanner(System.in);
            String ocspNameInput = in.nextLine();
            ObjectOutputStream caNameFileOutput = new ObjectOutputStream(new FileOutputStream(ocspServerPath + "ocspName.dat"));
            caNameFileOutput.writeObject(ocspNameInput);
            caNameFileOutput.close();

            ObjectInputStream caNameFileInput = new ObjectInputStream(new FileInputStream(ocspServerPath + "ocspName.dat"));
            ocspName = (String) caNameFileInput.readObject();
        } else {
            try {
                ObjectInputStream caNameFileInput = new ObjectInputStream(new FileInputStream(ocspServerPath + "ocspName.dat"));
                ocspName = (String) caNameFileInput.readObject();
            } catch (Exception e) {
                System.out.println("При получении имени УЦ произошла ошибка");
            }
        }
    }

    public static void checkStartConfigure(CertificateAuthority ocsp, PrivateKey ocspKey, X500Name ocspSubject) throws IOException {
        if (!new File(ocspServerPath + "client" + ocspName + "Cert.crt").exists()) {
            System.out.println("Отправляем запрос на получение сертификата УЦ.");
            try {
                // Создаем сокет и подключаемся к серверу
                Socket caSocket = new Socket(serverHostName, caPort);
                System.out.println("Подключен к серверу " + caSocket.getRemoteSocketAddress());
                // Создаем каналы записи и чтения
                DataOutputStream out = new DataOutputStream(caSocket.getOutputStream());
                DataInputStream in = new DataInputStream(caSocket.getInputStream());

                // Генерируем ключи
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
                keyGen.initialize(2048);
                KeyPair keyPair = keyGen.generateKeyPair();

                if (!new File(ocspServerPath + "privateKey.key").exists()) {
                    // Сохраняем приватный ключ в файл
                    PrivateKey privateKey = keyPair.getPrivate();
                    byte[] privateKeyEncoded = privateKey.getEncoded();
                    PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyEncoded);
                    FileOutputStream privateKeyStream = new FileOutputStream(ocspServerPath + "privateKey.key");
                    privateKeyStream.write(privateKeySpec.getEncoded());
                    privateKeyStream.close();
                }
                if (!new File(ocspServerPath + "publicKey.key").exists()) {
                    // Сохраняем публичный ключ в файл
                    PublicKey publicKey = keyPair.getPublic();
                    byte[] publicKeyEncoded = publicKey.getEncoded();
                    X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyEncoded);
                    FileOutputStream publicKeyStream = new FileOutputStream(ocspServerPath + "publicKey.key");
                    publicKeyStream.write(publicKeySpec.getEncoded());
                    publicKeyStream.close();
                }

                java.security.interfaces.RSAPublicKey rsaPublicKey = (java.security.interfaces.RSAPublicKey) keyPair.getPublic();
                java.security.interfaces.RSAPrivateKey rsaPrivateKey = (java.security.interfaces.RSAPrivateKey) keyPair.getPrivate();

                SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(rsaPublicKey.getEncoded());

                CertificationRequestInfo certificationRequestInfo = new CertificationRequestInfo(ocspSubject, subjectPublicKeyInfo, null);

                // Создаем объект AlgorithmIdentifier из алгоритма подписи
                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.1.1.11"), DERNull.INSTANCE);

                // Создаем подпись запроса на сертификат
                Signature signature = Signature.getInstance("SHA256withRSA");
                signature.initSign((PrivateKey) rsaPrivateKey);
                signature.update(certificationRequestInfo.getEncoded());
                byte[] signatureBytes = signature.sign();
                DERBitString derBitString = new DERBitString(signatureBytes);

                // Создаем объект CertificationRequest из CertificationRequestInfo, AlgorithmIdentifier и подписи
                CertificationRequest certificationRequest = new CertificationRequest(certificationRequestInfo, algorithmIdentifier, derBitString);

                // Создаем PKCS#10 запрос на сертификат
                PKCS10CertificationRequest csr = new PKCS10CertificationRequest(certificationRequest);

                // Отправляем запрос на сервер
                out.writeInt(csr.getEncoded().length);
                out.write(csr.getEncoded());
                out.flush();
                System.out.println("Запрос на сертификат отправлен на сервер");

                int fileSize = in.readInt();
                byte[] fileBytes = new byte[fileSize];
                int bytesRead = 0;
                while (bytesRead < fileSize) {
                    int count = in.read(fileBytes, bytesRead, fileSize - bytesRead);
                    if (count == -1) {
                        // Если получили конец потока раньше, чем получили весь файл, выбрасываем исключение
                        throw new IOException("Unexpected end of stream");
                    }
                    bytesRead += count;
                }
                // Сохраняем ответ в файл
                FileOutputStream fos = new FileOutputStream(ocspServerPath + in.readUTF());
                fos.write(fileBytes);
                fos.close();

                System.out.println("Файл сохранен, размер: " + fileSize + " байт");

                // Закрываем соединение
                caSocket.close();
                System.out.println("Соединение с сервером закрыто");
            } catch (
                    ConnectException e) {
                System.out.println("Извините, неполадки с соединением. " +
                        "Возможно сервер сейчас не доступен.");
            } catch (
                    IOException e) {
                e.printStackTrace();
            } catch (
                    NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
                throw new RuntimeException(e);
            }
            ObjectOutputStream privateKeyToFile = new ObjectOutputStream(new FileOutputStream(ocspServerPath + "privateKeyObj.dat"));
            privateKeyToFile.writeObject(ocsp.getPrivateKey());
            privateKeyToFile.close();

            try {
                try (ObjectInputStream keyCheck = new ObjectInputStream(new FileInputStream(ocspServerPath + "privateKeyObj.dat"))) {
                    ocspKey = (PrivateKey) keyCheck.readObject();
                } catch (IOException | ClassNotFoundException e) {
                    System.out.println("Error loading private key: " + e.getMessage());
                    System.exit(1);
                }
            } catch (Exception ex) {
                System.out.println("Error generating self-signed certificate: " + ex.getMessage());
                System.exit(1);
            }
        } else {
            try (ObjectInputStream keyCheck = new ObjectInputStream(new FileInputStream(ocspServerPath + "privateKeyObj.dat"))) {
                ocspKey = (PrivateKey) keyCheck.readObject();
                ocsp.loadPrivateKey(ocspKey);
            } catch (IOException | ClassNotFoundException e) {
                System.out.println("Error loading private key: " + e.getMessage());
                System.exit(1);
            }
        }
    }
}
