package ca;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;
import java.util.Scanner;

/**
 * @author Denis Popolamov
 */
public class CAServer {
    static int port = 9999;
    static String caName;
    static String serverPath = "src/main/resources/ca/server/";
    static String clientPath = "src/main/resources/ca/client/";

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, CertificateException, OperatorCreationException, InvalidKeySpecException, ClassNotFoundException {

        checkCANameFile(); // Проверка на наличие файла с именем УЦ

        CertificateAuthority caObj = new CertificateAuthority(caName);
        PrivateKey caKey = caObj.getPrivateKey();

        checkStartConfigure(caObj, caKey); // Настройка УЦ при первом запуске

        //createCertificate(caObj);
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
            System.out.println("DataInputStream created");

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
                } catch (IOException e) {
                    throw new RuntimeException(e);
                } catch (CertificateException e) {
                    throw new RuntimeException(e);
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException(e);
                } catch (NoSuchProviderException e) {
                    throw new RuntimeException(e);
                } catch (OperatorCreationException e) {
                    throw new RuntimeException(e);
                }
                try {
                    File file = new File("src/main/resources/ca/client/" + response);
                    byte[] buffer = new byte[(int) file.length()];
                    try (FileInputStream fileInputStream = new FileInputStream(file)) {
                        fileInputStream.read(buffer);
                    }
                    out.writeInt(buffer.length); // отправляем размер файла
                    out.write(buffer); // отправляем содержимое файла
                    out.writeUTF(response); // отправляем текстовый ответ
                    out.flush();
                    clientSocket.setSoTimeout(10000);
                } catch (IOException e) {
                    e.printStackTrace();
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

    public static String handleRequest(CertificateAuthority ca, PKCS10CertificationRequest csr) throws CertificateException, NoSuchAlgorithmException, IOException, NoSuchProviderException, OperatorCreationException {
        // Обработка запроса клиента
        SubjectPublicKeyInfo publicKeyInfo = csr.getSubjectPublicKeyInfo();

// Create a PublicKey object from the SubjectPublicKeyInfo
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(new BouncyCastleProvider());
        PublicKey publicKey = converter.getPublicKey(publicKeyInfo);
        String cert = createCertificate(ca, csr.getSubject().toString(), publicKey);
        System.out.println(cert.toString());
//        if (cert == request) {
        return cert;
//        } else {
//            return "Что то пошло не так при создании сертификата, проблема со стороны сервера";
//        }
    }

    public static String createCertificate(CertificateAuthority ca, String certificateName, PublicKey publicKey) throws NoSuchAlgorithmException, NoSuchProviderException, CertificateException, OperatorCreationException, IOException {
        String subjName = certificateName;
        subjName = certificateName.substring(3);
        // Выдача сертификата клиенту
        ca.savePrivateKey(clientPath + "client" + subjName + "PrivateKey.pem");

        X509Certificate clientCert = ca.issueCertificate(publicKey, new Date(), new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000L), subjName);
        String certFileName = "client" + subjName + "Cert.crt";
        FileOutputStream fos = new FileOutputStream(clientPath + certFileName);
        fos.write(clientCert.getEncoded());
        fos.close();
        return certFileName;
    }

    public static void checkCANameFile() throws IOException, ClassNotFoundException {
        if (!new File(serverPath + "caName.dat").exists()) {
            System.out.println("Задайте название вашего УЦ: ");
            Scanner in = new Scanner(System.in);
            String caNameInput = in.nextLine();
            ObjectOutputStream caNameFileOutput = new ObjectOutputStream(new FileOutputStream(serverPath + "caName.dat"));
            caNameFileOutput.writeObject(caNameInput);
            caNameFileOutput.close();

            ObjectInputStream caNameFileInput = new ObjectInputStream(new FileInputStream(serverPath + "caName.dat"));
            caName = (String) caNameFileInput.readObject();
        } else {
            try {
                ObjectInputStream caNameFileInput = new ObjectInputStream(new FileInputStream(serverPath + "caName.dat"));
                caName = (String) caNameFileInput.readObject();
            } catch (Exception e) {
                System.out.println("При получении имени УЦ произошла ошибка");
            }
        }
    }

    public static void checkStartConfigure(CertificateAuthority ca, PrivateKey caKey) {
        if (!new File(serverPath + "caCert.crt").exists()) {
            System.out.println("Создаём caCert.crt.");
            try {
                // Создание самоподписанного сертификата
                X509Certificate selfSignedCert = ca.createSelfSignedCertificate(new Date(), new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000L));
                FileOutputStream caCertFile = new FileOutputStream(serverPath + "caCert.crt");
                caCertFile.write(selfSignedCert.getEncoded());
                caCertFile.close();
                FileOutputStream caPublicKeyFile = new FileOutputStream(serverPath + "caPublicKey.key");
                caPublicKeyFile.write(selfSignedCert.getPublicKey().getEncoded());
                caPublicKeyFile.close();
                FileOutputStream caPrivateKeyFile = new FileOutputStream(serverPath + "caPrivateKey.key");
                caPrivateKeyFile.write(ca.getPrivateKey().getEncoded());
                caPrivateKeyFile.close();
                ObjectOutputStream privateKeyToFile = new ObjectOutputStream(new FileOutputStream(serverPath + "privateKeyObj.dat"));
                privateKeyToFile.writeObject(ca.getPrivateKey());
                privateKeyToFile.close();
                try (ObjectInputStream keyCheck = new ObjectInputStream(new FileInputStream(serverPath + "privateKeyObj.dat"))) {
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
            try (ObjectInputStream keyCheck = new ObjectInputStream(new FileInputStream(serverPath + "privateKeyObj.dat"))) {
                caKey = (PrivateKey) keyCheck.readObject();
                ca.loadPrivateKey(caKey);
            } catch (IOException | ClassNotFoundException e) {
                System.out.println("Error loading private key: " + e.getMessage());
                System.exit(1);
            }
        }
    }
}
