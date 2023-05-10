package ocsp;

import logic.OCSPServerLogic;
import model.CertificateAuthority;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import settings.OCSPServerSettings;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class OCSPServer {

    static int port = 8888;
    static String ocspName;
    static String ocspServerPath = "src/main/resources/server/ocsp/";
    static String ocspPath = "../ocsp/";

    public static void main(String[] args) throws IOException,
            ClassNotFoundException, NoSuchAlgorithmException,
            CertificateException, InvalidKeySpecException {

        OCSPServerSettings.checkOCSPServerNameFile();

        X500Name ocspSubject = new X500Name("CN=" + ocspName);
        CertificateAuthority ocspObj = new CertificateAuthority(ocspName);
        PrivateKey ocspKey = ocspObj.getPrivateKey();

        OCSPServerSettings.checkOCSPServerStartConfigure(ocspObj, ocspKey, ocspSubject);
        FileInputStream fis = new FileInputStream(ocspPath + "client" + ocspName + "Cert.crt");
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate ocspCertificate = (X509Certificate) cf.generateCertificate(fis);

        File filePrivateKey = new File(ocspPath + "privateKey.key");
        byte[] encodedPrivateKey = Files.readAllBytes(filePrivateKey.toPath());

        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey ocspPrivateKey = keyFactory.generatePrivate(privateKeySpec);

        ServerSocket serverSocket = new ServerSocket(port);
        System.out.println("Сервер запущен на порту " + port);

        while (true) {
            Socket clientSocket = serverSocket.accept(); // Ждем подключения клиента
            System.out.println("#-----------------------------------------------#");
            System.out.println("Client connected " + clientSocket.getInetAddress());
            // канал записи в сокет
            DataOutputStream oos = new DataOutputStream(clientSocket.getOutputStream());

            // канал чтения из сокета
            DataInputStream ois = new DataInputStream(clientSocket.getInputStream());

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
                    OCSPResp ocspResp = OCSPServerLogic.makeOcspResponse(ocspCertificate, ocspPrivateKey, ocspReq);
                    System.out.println("Requested name:" + ocspReq.getRequestorName().getName());
                    System.out.println("Request length: " + ocspReq.getRequestList().length);
                    switch (ocspResp.getStatus()) {
                        case 0 -> System.out.println("OCSPResponse status: \u001B[32mGOOD\u001B[0m");
                        case 1 -> System.out.println("OCSPResponse status: \u001B[31mMALFORMED REQUEST\u001B[0m");
                        case 2 -> System.out.println("OCSPResponse status: \u001B[31mINTERNAL ERROR\u001B[0m");
                        case 3 -> System.out.println("OCSPResponse status: \u001B[33mTRY LATER\u001B[0m");
                        case 5 -> System.out.println("OCSPResponse status: \u001B[33mSIG REQUIRED\u001B[0m");
                        case 6 -> System.out.println("OCSPResponse status: \u001B[31mUNAUTHORIZED\u001B[0m");
                        default -> System.out.println("OCSPResponse status: " + ocspResp.getStatus());
                    }
                    byte[] ocspResponseBytes = ocspResp.getEncoded();
                    oos.writeInt(ocspResponseBytes.length);
                    oos.write(ocspResponseBytes);
                    oos.writeUTF(ocspName);
                    oos.flush();
                    clientSocket.setSoTimeout(100000);
                } catch (Exception e) {
                    e.printStackTrace();
                } finally {
                    try {
                        // Закрываем соединение с клиентом
                        clientSocket.close();
                        System.out.println("Connect with client " + clientSocket.getInetAddress() + " closed");
                        System.out.println("#-----------------------------------------------#");
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }).start();
        }
    }
}
