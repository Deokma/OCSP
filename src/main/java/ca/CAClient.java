package ca;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.*;
import java.net.ConnectException;
import java.net.Socket;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;

/**
 * @author Denis Popolamov
 */

public class CAClient {
    static String serverHostname = "localhost"; // Имя сервера, к которому подключаемся
    static int port = 9999; // Порт сервера
    static String clientName;
    static String clientNamePath = "src/main/resources/client/ca/";
    static String clientPath = "../client/ca/";

    public static void main(String[] args) throws IOException, ClassNotFoundException {
        new File(clientNamePath).mkdirs();
        new File(clientPath).mkdirs();

        checkSubjNameFile();

        X500Name subject = new X500Name("CN=" + clientName);

        try {
            // Создаем сокет и подключаемся к серверу
            Socket socket = new Socket(serverHostname, port);
            System.out.println("Подключен к серверу " + socket.getRemoteSocketAddress());
            // Создаем каналы записи и чтения
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            DataInputStream in = new DataInputStream(socket.getInputStream());

            // Генерируем ключи
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair keyPair = keyGen.generateKeyPair();

            if (!new File(clientPath + "privateKey.key").exists()) {
                // Сохраняем приватный ключ в файл
                PrivateKey privateKey = keyPair.getPrivate();
                byte[] privateKeyEncoded = privateKey.getEncoded();
                PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyEncoded);
                FileOutputStream privateKeyStream = new FileOutputStream(clientPath + "privateKey.key");
                privateKeyStream.write(privateKeySpec.getEncoded());
                privateKeyStream.close();
            }
            if (!new File(clientPath + "publicKey.key").exists()) {
                // Сохраняем публичный ключ в файл
                PublicKey publicKey = keyPair.getPublic();
                byte[] publicKeyEncoded = publicKey.getEncoded();
                X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyEncoded);
                FileOutputStream publicKeyStream = new FileOutputStream(clientPath + "publicKey.key");
                publicKeyStream.write(publicKeySpec.getEncoded());
                publicKeyStream.close();
            }

            java.security.interfaces.RSAPublicKey rsaPublicKey = (java.security.interfaces.RSAPublicKey) keyPair.getPublic();
            java.security.interfaces.RSAPrivateKey rsaPrivateKey = (java.security.interfaces.RSAPrivateKey) keyPair.getPrivate();

            SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(rsaPublicKey.getEncoded());

            CertificationRequestInfo certificationRequestInfo = new CertificationRequestInfo(subject, subjectPublicKeyInfo, null);

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
            FileOutputStream fos = new FileOutputStream(clientPath + in.readUTF());
            fos.write(fileBytes);
            fos.close();

            System.out.println("Файл сохранен, размер: " + fileSize + " байт");

            // Закрываем соединение
            socket.close();
            System.out.println("Соединение с сервером закрыто");
        } catch (
                ConnectException e) {
            System.out.println("Извините, неполадки с соединением. " +
                    "Возможно сервер сейчас не доступен.");
        } catch (
                IOException e) {
            e.printStackTrace();
        } catch (
                NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    public static void checkSubjNameFile() throws IOException, ClassNotFoundException {
        if (!new File(clientNamePath + "subjectName.dat").exists()) {
            Scanner scanner = new Scanner(System.in);
            System.out.print("Пожалуйста введите имя пользователя: ");
            clientName = scanner.nextLine();
            ObjectOutputStream subjectNameOut = new ObjectOutputStream(new FileOutputStream(clientNamePath + "subjectName.dat"));
            subjectNameOut.writeObject(clientName);
            subjectNameOut.close();
        } else {
            ObjectInputStream subjectNameIn = new ObjectInputStream(new FileInputStream(clientNamePath + "subjectName.dat"));
            clientName = (String) subjectNameIn.readObject();
        }
    }
}
