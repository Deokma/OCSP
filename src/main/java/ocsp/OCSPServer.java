package ocsp;

import ca.CertificateAuthority;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.ocsp.*;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.cert.ocsp.jcajce.JcaBasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.*;
import java.net.ConnectException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.nio.file.Files;
import java.security.*;
import java.security.Signature;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Scanner;

public class OCSPServer {
    static int port = 8888;
    static int caPort = 9999;
    static String ocspServerPath = "src/main/resources/ocsp/server/";
    static String ocspName;
    static String serverHostName = "localhost";

    public static void main(String[] args) throws IOException, ClassNotFoundException, NoSuchAlgorithmException, NoSuchProviderException {

        checkOCSPNameFile();
        X500Name ocspSubject = new X500Name("CN=" + ocspName);

        CertificateAuthority ocspObj = new CertificateAuthority(ocspName);
        PrivateKey ocspKey = ocspObj.getPrivateKey();
        checkStartConfigure(ocspObj, ocspKey, ocspSubject);

        ServerSocket serverSocket = new ServerSocket(port);
        System.out.println("Сервер запущен на порту " + port);

        while (true) {
            Socket clientSocket = serverSocket.accept(); // Ждем подключения клиента
            System.out.println("Подключился клиент " + clientSocket.getInetAddress());

            // канал записи в сокет
            DataOutputStream oos = new DataOutputStream(clientSocket.getOutputStream());
            System.out.println("DataOutputStream created");

            // канал чтения из сокета
            DataInputStream ois = new DataInputStream(clientSocket.getInputStream());
            System.out.println("DataInputStream created");

            new Thread(() -> {
                try {
                    // получить длину байтового потока с запросом
                    int ocspRequestLength = ois.readInt();
                    // создать буфер для запроса
                    byte[] ocspRequest = new byte[ocspRequestLength];
                    // считать запрос в буфер
                    ois.readFully(ocspRequest);

                    // создать объект OCSPRequest из буфера с запросом
                    OCSPRequest request = OCSPRequest.getInstance(ocspRequest);

                    // обработать запрос и получить ответ
                    byte[] ocspResponse = handleOcspRequest(request);
                    if (ocspResponse == null) {
                        throw new RuntimeException("OCSP Response is null");
                    }
                    // отправить ответ клиенту
                    oos.writeInt(ocspResponse.length);
                    oos.write(ocspResponse);
                    oos.flush();
                } catch (IOException e) {
                    e.printStackTrace();
                } catch (Exception e) {
                    throw new RuntimeException(e);
                } finally {
                    try {
                        // Закрываем соединение с клиентом
                        clientSocket.close();
                        System.out.println("Соединение с клиентом " + clientSocket.getInetAddress() + " закрыто");
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }).start();

            // получить длину байтового потока с запросом
            //int ocspRequestLength = ois.readInt();
            // создать буфер для запроса
            //byte[] ocspRequest = new byte[ocspRequestLength];
            // считать запрос в буфер
            //ois.readFully(ocspRequest);

            // создать объект OCSPRequest из буфера с запросом
            //OCSPRequest request = OCSPRequest.getInstance(ocspRequest);

            // проверить, что запрос сформирован правильно
            // String response = handleRequest(request);
            //if (response == null) {
            // если запрос невалиден, отправить сообщение об ошибке
            //   oos.writeUTF("OCSP request is invalid");
            //} else {
            // если запрос валиден, обработать его и отправить ответ
//                OCSPResponseStatus status = new OCSPResponseStatus(1);
//                OCSPResponse ocspResponse = new OCSPResponse(status, null);
//                byte[] buffer = ocspResponse.getEncoded();
//
//                oos.writeInt(buffer.length);
//                oos.write(buffer);
//                oos.flush();
//                clientSocket.setSoTimeout(10000);
            //byte[] ocspResponse = // получить ответ в виде байтового потока
            //      oos.writeInt(ocspResponse.length); // отправить длину байтового потока
            //oos.write(ocspResponse); // отправить байтовый поток
        }

// очистить поток
        // oos.flush();

        //String entry = in.readUTF();

        //System.out.println("READ from client message - " + entry);

//            if (entry.equalsIgnoreCase("quit")) {
//                System.out.println("Client initialize connections suicide ...");
//                out.writeUTF("Server reply - " + entry + " - OK");
//                out.flush();
//                break;
//            }

        // Обрабатываем запрос клиента в новом потоке
//            new Thread(() -> {
//                //String response = handleRequest(entry);
//                try {
//                    if (response == null) {
//                        // если запрос невалиден, отправить сообщение об ошибке
//                        oos.writeUTF("OCSP request is invalid");
//                    } else {
//                        // если запрос валиден, обработать его и отправить ответ
//                        OCSPResponseStatus status = new OCSPResponseStatus(1);
//                        OCSPResponse ocspResponse = new OCSPResponse(status, null);
//                        byte[] buffer = ocspResponse.getEncoded();
//
//                        oos.writeInt(buffer.length);
//                        oos.write(buffer);
//                        oos.flush();
//                        clientSocket.setSoTimeout(10000);
//                        //byte[] ocspResponse = // получить ответ в виде байтового потока
//                        //      oos.writeInt(ocspResponse.length); // отправить длину байтового потока
//                        //oos.write(ocspResponse); // отправить байтовый поток
//                    }
//                } catch (IOException e) {
//                    throw new RuntimeException(e);
//                }
//
////                try {
////                    // Отправляем ответ клиенту
////                    out.writeUTF(response);
////                    out.flush();
////                } catch (IOException e) {
////                    e.printStackTrace();
////                } finally {
////                    try {
////                        // Закрываем соединение с клиентом
////                        clientSocket.close();
////                        System.out.println("Соединение с клиентом " + clientSocket.getInetAddress() + " закрыто");
////                    } catch (IOException e) {
////                        e.printStackTrace();
////                    }
////                }
//            }).start();


    }
    public static OCSPResp makeOcspResponse(
            X509Certificate caCert, PrivateKey caPrivateKey, OCSPReq ocspReq)
            throws OCSPException, OperatorCreationException, CertificateEncodingException
    {
        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder()
                .setProvider("BCFIPS").build();
        BasicOCSPRespBuilder respGen = new JcaBasicOCSPRespBuilder(
                caCert.getPublicKey(), digCalcProv.get(RespID.HASH_SHA1));
        CertificateID certID = ocspReq.getRequestList()[0].getCertID();
        // magic happens…
        respGen.addResponse(certID, CertificateStatus.GOOD);
        BasicOCSPResp resp = respGen.build(
                new JcaContentSignerBuilder("SHA384withECDSA").setProvider("BCFIPS").build(caPrivateKey),
                new X509CertificateHolder[]{new JcaX509CertificateHolder(caCert)},
                new Date());
        OCSPRespBuilder rGen = new OCSPRespBuilder();
        return rGen.build(OCSPRespBuilder.SUCCESSFUL, resp);
    }
    public static boolean isGoodCertificate(
            OCSPResp ocspResp, X509Certificate caCert, X509Certificate eeCert)
            throws OperatorCreationException, OCSPException, CertificateEncodingException
    {
        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder()
                .setProvider("BCFIPS").build();
        // SUCCESSFUL here means the OCSP request worked, it doesn't mean the certificate is valid.
        if (ocspResp.getStatus() == OCSPRespBuilder.SUCCESSFUL)
        {
            BasicOCSPResp resp = (BasicOCSPResp)ocspResp.getResponseObject();
            // make sure response is signed by the appropriate CA
            if (resp.isSignatureValid(new JcaContentVerifierProviderBuilder()
                    .setProvider("BCFIPS").build(caCert.getPublicKey())))
            {
                // return the actual status of the certificate – null means valid.
                return resp.getResponses()[0].getCertID().matchesIssuer(
                        new JcaX509CertificateHolder(caCert), digCalcProv)
                        && resp.getResponses()[0].getCertID().getSerialNumber()
                        .equals(eeCert.getSerialNumber())
                        && resp.getResponses()[0].getCertStatus() == null;
            }
        }
        throw new IllegalStateException("OCSP Request Failed");
    }
    // Метод для обработки OCSP запросов
    private static byte[] handleOcspRequest(OCSPRequest request) throws IOException, CertificateException, OperatorCreationException, OCSPException, NoSuchAlgorithmException, InvalidKeySpecException {
        // TODO: Здесь нужно добавить код для обработки OCSP запросов
        // Получить TBSRequest из OCSPRequest
        TBSRequest tbsRequest = request.getTbsRequest();

        // Открыть файл сертификата
        FileInputStream fis = new FileInputStream(ocspServerPath + "clientMyOCSPCert.crt");
        // Создать объект CertificateFactory
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        // Получить сертификат из потока
        X509Certificate signingCert = (X509Certificate) cf.generateCertificate(fis);
        // Закрыть поток ввода
        fis.close();

        File keyFile = new File(ocspServerPath + "privateKey.key");
        byte[] keyBytes = Files.readAllBytes(keyFile.toPath());
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA"); // или другой алгоритм
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);


        // Получить список сертификатов из TBSRequest
        ASN1Sequence certSequence = tbsRequest.getRequestList();
        ASN1Encodable[] certList = certSequence.toArray();
        List<X509Certificate> certificates = new ArrayList<>();
        for (ASN1Encodable certEncodable : certList) {
            X509Certificate cert;
            try {
                cert = new JcaX509CertificateConverter().getCertificate(
                        new X509CertificateHolder(certEncodable.toASN1Primitive().getEncoded())
                );
                certificates.add(cert);
            } catch (CertificateException e) {
                e.printStackTrace();
            }
        }

        // Создать объект BasicOCSPRespBuilder
        BasicOCSPRespBuilder builder = new JcaBasicOCSPRespBuilder(
                signingCert.getPublicKey(), new JcaDigestCalculatorProviderBuilder().setProvider("BC").build().get(CertificateID.HASH_SHA1)
        );

// Добавить статусы проверки сертификатов
        for (X509Certificate cert : certificates) {
            CertificateID certId;
            try {
                certId = new CertificateID(
                        new JcaDigestCalculatorProviderBuilder()
                                .setProvider("BC")
                                .build()
                                .get(CertificateID.HASH_SHA1),
                        new JcaX509CertificateHolder(cert),
                        cert.getSerialNumber()
                );

                builder.addResponse(certId,
                        new RevokedStatus(
                                new RevokedInfo(
                                        new ASN1GeneralizedTime(new Date()),
                                        CRLReason.lookup(CRLReason.keyCompromise)
                                )
                        )
                );


            } catch (OCSPException | CertificateEncodingException e) {
                e.printStackTrace();
            }
        }

// Создать объект BasicOCSPResp
        BasicOCSPResp ocspResp = builder.build(
                new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(privateKey),
                new org.bouncycastle.cert.X509CertificateHolder[]{new JcaX509CertificateHolder(signingCert)},
                new Date()
        );


// Получить байты BasicOCSPResp
        return ocspResp.getEncoded();

        //return null;
    }

//    private static byte[] handleOcspRequest(OCSPRequest request) throws Exception {
//        // Получить список сертификатов из запроса
//        ASN1Sequence certs = request.getTbsRequest().getRequestList();
//        List<X509Certificate> certsList = new ArrayList<>();
//
//        // Открыть файл сертификата
//        FileInputStream fis = new FileInputStream(ocspServerPath + "clientMyOCSPCert.crt");
//// Создать объект CertificateFactory
//        CertificateFactory cf = CertificateFactory.getInstance("X.509");
//// Получить сертификат из потока
//        X509Certificate signingCert = (X509Certificate) cf.generateCertificate(fis);
//// Закрыть поток ввода
//        fis.close();
//
//        // Парсить каждый сертификат из последовательности
//        for (int i = 0; i < certs.size(); i++) {
//            X509CertificateHolder holder = (X509CertificateHolder) certs.getObjectAt(i);
//            try {
//                X509Certificate cert = new JcaX509CertificateConverter().getCertificate(holder);
//                certsList.add(cert);
//            } catch (CertificateException e) {
//                e.printStackTrace();
//            }
//        }
//
//        // Создать генератор OCSP ответа
//        JcaBasicOCSPRespBuilder builder = new JcaBasicOCSPRespBuilder((PublicKey) new X509CertificateHolder(signingCert.getEncoded()), (DigestCalculator) new JcaDigestCalculatorProviderBuilder().build());
//
//// Добавить статус проверки для каждого сертификата
//        for (X509Certificate cert : certsList) {
//            CertificateID id = new CertificateID(new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1), new X509CertificateHolder(cert.getEncoded()), cert.getSerialNumber());
//            builder.addRevokedResponse(id, new Date(), CRLReason.unspecified);
//        }
//
//        BasicOCSPResp response = builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(signingKey), null, null);
//        return response.getEncoded();
//
//        try {
//            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(signingKey);
//            response = builder.build(signer, null, new Date());
//        } catch (OperatorCreationException e) {
//            e.printStackTrace();
//        } catch (OCSPException e) {
//            e.printStackTrace();
//        }
//
//        // Конвертировать OCSP ответ в байтовый массив
//        byte[] encoded = response.getEncoded();
//        return encoded;
//    }


    private static Key getKeyFromKeyStore(String keystorePath, String keystorePassword, String keyAlias) throws Exception {
        FileInputStream is = new FileInputStream(keystorePath);
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(is, keystorePassword.toCharArray());
        Key key = keystore.getKey(keyAlias, keystorePassword.toCharArray());
        return key;
    }


    public static String handleRequest(OCSPRequest request) {
        // Обработка запроса клиента
//        if (request.equalsIgnoreCase("hello")) {
//            return "Привет, клиент!";
//        } else {
//            return "Я не знаю, что ответить на это сообщение";
//        }
        return "Всё ок";
    }

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
