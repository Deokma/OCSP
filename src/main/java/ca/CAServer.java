package ca;

import connect.DBManager;
import logic.CAServerLogic;
import model.CertificateAuthority;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import settings.CAServerSettings;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

public class CAServer {
    static int port = 9999;
    static String caName;
    static String caCertificatesPath = "../ca/certificates/";
    private static final DigestCalculatorProvider DIG_CALC_PROV;

    static {
        try {
            DIG_CALC_PROV = new JcaDigestCalculatorProviderBuilder().build();
        } catch (OperatorCreationException e) {
            throw new RuntimeException(e);
        }
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, ClassNotFoundException {

        DBManager db = new DBManager();
       // CAServerSettings caServerSettings = new CAServerSettings();
        CAServerSettings.checkCAServerNameFile(); // Проверка на наличие файла с именем УЦ

        CertificateAuthority caObj = new CertificateAuthority(caName);
        PrivateKey caKey = caObj.getPrivateKey();

        CAServerSettings.checkCAServerStartConfigure(caObj, caKey);

        ServerSocket serverSocket = new ServerSocket(port);
        System.out.println("Server started with port " + port);
        System.out.println("CA: \"" + caName + "\" ready to work.");

        while (true) {
            Socket clientSocket = serverSocket.accept(); // Ждем подключения клиента
            System.out.println("Client connected " + clientSocket.getInetAddress());

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
                    response = CAServerLogic.handleRequest(caObj, request);
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

                    db.addCertificate(certId, clientCert, new Date(),
                            new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000L), "GOOD");
                    out.writeInt(buffer.length); // отправляем размер файла
                    out.write(buffer); // отправляем содержимое файла
                    out.writeUTF(response); // отправляем текстовый ответ
                    out.flush();
                    clientSocket.setSoTimeout(10000);
                } catch (IOException e) {
                    e.printStackTrace();
                } catch (CertificateException | OperatorCreationException | OCSPException e) {
                    throw new RuntimeException(e);
                } finally {
                    try {
                        // Закрываем соединение с клиентом
                        clientSocket.close();
                        System.out.println("Connect with " + clientSocket.getInetAddress() + " closed");
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }).start();
        }
    }
}
