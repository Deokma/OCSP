package ca;

import connect.DBManager;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;
import java.util.Scanner;

/**
 * Сервер УЦ
 *
 * @author Denis Popolamov
 */
public class CAServer {
    static int port = 9999;
    static String caName;
    static String caServerPath = "src/main/resources/ca/";
    static String caPath = "../ca/";
    static String caCertificatesPath = "../ca/certificates/";
    static String caKeysPath = "../ca/keys/";
    //static String caClientPath = "src/main/resources/ca/client/";
    private static final DigestCalculatorProvider DIG_CALC_PROV;

    static {
        try {
            DIG_CALC_PROV = new JcaDigestCalculatorProviderBuilder().build();
        } catch (OperatorCreationException e) {
            throw new RuntimeException(e);
        }
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, CertificateException, OperatorCreationException, InvalidKeySpecException, ClassNotFoundException {
        DBManager db = new DBManager();
        new File(caServerPath).mkdirs();
        new File(caPath).mkdirs();
        new File(caCertificatesPath).mkdirs();
        new File(caKeysPath).mkdirs();
        checkCANameFile(); // Проверка на наличие файла с именем УЦ

        CertificateAuthority caObj = new CertificateAuthority(caName);
        PrivateKey caKey = caObj.getPrivateKey();

        checkStartConfigure(caObj, caKey); // Настройка УЦ при первом запуске

        ServerSocket serverSocket = new ServerSocket(port);
        System.out.println("Сервер запущен на порту " + port);
        System.out.println("УЦ: \"" + caName + "\" готов к работе.");

        while (true) {
            Socket clientSocket = serverSocket.accept(); // Ждем подключения клиента
            System.out.println("Подключился клиент " + clientSocket.getInetAddress());

            // канал записи в сокет
            DataOutputStream out = new DataOutputStream(clientSocket.getOutputStream());

            // канал чтения из сокета
            DataInputStream in = new DataInputStream(clientSocket.getInputStream());

            new Thread(() -> {
                String response;
                try {
                    // Получаем размер файла
                    int fileSize = in.readInt();
                    byte[] fileBytes = new byte[fileSize];
                    int bytesRead = 0;
                    // Читаем байты из сокета, пока не получим весь файл
                    while (bytesRead < fileSize) {
                        int count = in.read(fileBytes, bytesRead, fileSize - bytesRead);
                        if (count == -1) {
                            // Если получили конец потока раньше, чем получили весь файл, выбрасываем исключение
                            throw new IOException("Unexpected end of stream");
                        }
                        bytesRead += count;
                    }
                    // Обработка запроса и получение ответа
                    PKCS10CertificationRequest request = new PKCS10CertificationRequest(fileBytes);
                    response = handleRequest(caObj, request);
                } catch (IOException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException |
                         OperatorCreationException e) {
                    throw new RuntimeException(e);
                }
                try {
                    File file = new File(caCertificatesPath + response);
                    FileInputStream fis = new FileInputStream(caCertificatesPath + response);
                    byte[] buffer = new byte[(int) file.length()];
                    try (FileInputStream fileInputStream = new FileInputStream(file)) {
                        fileInputStream.read(buffer);
                    }
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    X509Certificate clientCert = (X509Certificate) cf.generateCertificate(fis);
                    CertificateID certId = new JcaCertificateID(
                            DIG_CALC_PROV.get(CertificateID.HASH_SHA1), clientCert, clientCert.getSerialNumber());

                    db.addCertificate(certId, clientCert, new Date(), new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000L), "GOOD");
                    out.writeInt(buffer.length); // отправляем размер файла
                    out.write(buffer); // отправляем содержимое файла
                    out.writeUTF(response); // отправляем текстовый ответ
                    out.flush();
                    clientSocket.setSoTimeout(10000);
                } catch (IOException e) {
                    e.printStackTrace();
                } catch (CertificateException e) {
                    throw new RuntimeException(e);
                } catch (OCSPException e) {
                    throw new RuntimeException(e);
                } catch (OperatorCreationException e) {
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
        }
    }

    /**
     * Запрос на обработку сертификата для клиента
     *
     * @param ca  объект УЦ
     * @param csr запрос на обработку сертификата
     * @return
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws NoSuchProviderException
     * @throws OperatorCreationException
     */
    public static String handleRequest(CertificateAuthority ca, PKCS10CertificationRequest csr) throws CertificateException, NoSuchAlgorithmException, IOException, NoSuchProviderException, OperatorCreationException {
        // Обработка запроса клиента
        SubjectPublicKeyInfo publicKeyInfo = csr.getSubjectPublicKeyInfo();

        // Create a PublicKey object from the SubjectPublicKeyInfo
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(new BouncyCastleProvider());
        PublicKey publicKey = converter.getPublicKey(publicKeyInfo);
        String cert = createCertificate(ca, csr.getSubject().toString(), publicKey);
        System.out.println("Создан сертификат: " + cert.toString());
        return cert;
    }

    /**
     * Создание сертификата
     *
     * @param ca              объект УЦ
     * @param certificateName имя для сертификата
     * @param publicKey       сгенерированный публичный ключ
     * @return имя сертификата
     * @throws CertificateException
     * @throws OperatorCreationException
     * @throws IOException
     */
    public static String createCertificate(CertificateAuthority ca, String certificateName, PublicKey publicKey) throws CertificateException, OperatorCreationException, IOException {
        String subjName = certificateName.substring(3);

        // Выдача сертификата клиенту
        //ca.savePrivateKey(caKeysPath + "client" + subjName + "PrivateKey.pem");

        X509Certificate clientCert = ca.issueCertificate(publicKey, new Date(), new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000L), subjName);

        String certFileName = "client" + subjName + "Cert.crt";
        String privateKeyFileName = "client" + subjName + "PrivateKey.pem";

        // Check if files already exist, if so add a numeric value to the file name
        int fileNumber = 0;
        while (new File(caCertificatesPath + certFileName).exists()) {
            fileNumber++;
            certFileName = "client" + subjName + "Cert" + fileNumber + ".crt";
        }
        fileNumber = 0;
        while (new File(caKeysPath + privateKeyFileName).exists()) {
            fileNumber++;
            privateKeyFileName = "client" + subjName + "PrivateKey" + fileNumber + ".pem";
        }

        // Save certificate and private key to files
        FileOutputStream fos = new FileOutputStream(caCertificatesPath + certFileName);
        fos.write(clientCert.getEncoded());
        fos.close();

        fos = new FileOutputStream(caKeysPath + privateKeyFileName);
        fos.write(ca.getPrivateKey().getEncoded());
        fos.close();

        return certFileName;
    }


    /**
     * Проверка на присутствие файла с именем УЦ
     *
     * @throws IOException
     * @throws ClassNotFoundException
     */
    public static void checkCANameFile() throws IOException, ClassNotFoundException {
     if (!new File(caServerPath + "caName.dat").exists()) {
            System.out.print("Задайте название вашего УЦ: ");
            Scanner in = new Scanner(System.in);
            String caNameInput = in.nextLine();
            ObjectOutputStream caNameFileOutput = new ObjectOutputStream(new FileOutputStream(caServerPath + "caName.dat"));
            caNameFileOutput.writeObject(caNameInput);
            caNameFileOutput.close();

            ObjectInputStream caNameFileInput = new ObjectInputStream(new FileInputStream(caServerPath + "caName.dat"));
            caName = (String) caNameFileInput.readObject();
        } else {
            try {
                ObjectInputStream caNameFileInput = new ObjectInputStream(new FileInputStream(caServerPath + "caName.dat"));
                caName = (String) caNameFileInput.readObject();
            } catch (Exception e) {
                System.out.println("При получении имени УЦ произошла ошибка");
            }
        }
    }

    /**
     * Метод для проверки всех необходимых файлов для работы УЦ
     *
     * @param ca    объект УЦ
     * @param caKey приватный ключ УЦ
     */
    public static void checkStartConfigure(CertificateAuthority ca, PrivateKey caKey) {
        if (!new File(caPath + "caCert.crt").exists()) {
            System.out.println("Создаём caCert.crt.");
            try {
                // Создание самоподписанного сертификата
                X509Certificate selfSignedCert = ca.createSelfSignedCertificate(new Date(), new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000L));
                FileOutputStream caCertFile = new FileOutputStream(caPath + "caCert.crt");
                caCertFile.write(selfSignedCert.getEncoded());
                caCertFile.close();
                FileOutputStream caPublicKeyFile = new FileOutputStream(caPath + "caPublicKey.key");
                caPublicKeyFile.write(selfSignedCert.getPublicKey().getEncoded());
                caPublicKeyFile.close();
                FileOutputStream caPrivateKeyFile = new FileOutputStream(caPath + "caPrivateKey.key");
                caPrivateKeyFile.write(ca.getPrivateKey().getEncoded());
                caPrivateKeyFile.close();
                ObjectOutputStream privateKeyToFile = new ObjectOutputStream(new FileOutputStream(caServerPath + "privateKeyObj.dat"));
                privateKeyToFile.writeObject(ca.getPrivateKey());
                privateKeyToFile.close();
                try (ObjectInputStream keyCheck = new ObjectInputStream(new FileInputStream(caServerPath + "privateKeyObj.dat"))) {
                    caKey = (PrivateKey) keyCheck.readObject();
                } catch (IOException | ClassNotFoundException e) {
                    System.out.println("Error loading private key: " + e.getMessage());
                    System.exit(1);
                }
            } catch (Exception ex) {
                System.out.println("Error generating self-signed certificate: " + ex.getMessage());
                System.exit(1);
            }
        } else {
            try (ObjectInputStream keyCheck = new ObjectInputStream(new FileInputStream(caServerPath + "privateKeyObj.dat"))) {
                caKey = (PrivateKey) keyCheck.readObject();
                ca.loadPrivateKey(caKey);
            } catch (IOException | ClassNotFoundException e) {
                System.out.println("Error loading private key: " + e.getMessage());
                System.exit(1);
            }
        }
    }
}
