package settings;

import model.CertificateAuthority;
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
import java.util.Properties;
import java.util.Scanner;

public class OCSPServerSettings extends Settings {


//    public OCSPServerSettings() throws IOException {
//        Properties prop = readPropertiesFile();
//
//    }

    public static void checkOCSPServerNameFile() throws IOException, ClassNotFoundException {
        readPropertiesFile();
        new File(ocspServerResourcesPath).mkdirs();
        new File(ocspServerPath).mkdirs();
        if (!new File(ocspServerResourcesPath + "ocspName.dat").exists()) {
            System.out.print("Enter name of your OCSP server: ");
            Scanner in = new Scanner(System.in);
            String ocspNameInput = in.nextLine();
            ObjectOutputStream caNameFileOutput = new ObjectOutputStream(new FileOutputStream(ocspServerResourcesPath +
                    "ocspName.dat"));
            caNameFileOutput.writeObject(ocspNameInput);
            caNameFileOutput.close();

            ObjectInputStream caNameFileInput = new ObjectInputStream(new FileInputStream(ocspServerResourcesPath +
                    "ocspName.dat"));
            ocspName = (String) caNameFileInput.readObject();
        } else {
            try {
                ObjectInputStream caNameFileInput = new ObjectInputStream(new FileInputStream(ocspServerResourcesPath +
                        "ocspName.dat"));
                ocspName = (String) caNameFileInput.readObject();
            } catch (Exception e) {
                System.out.println("An error occurred while getting the name of the OCSP");
            }
        }
    }

    public static void checkOCSPServerStartConfigure(CertificateAuthority ocsp, PrivateKey ocspKey, X500Name ocspSubject) throws
            IOException {
        if (!new File(ocspServerPath + "client" + ocspName + "Cert.crt").exists()) {
            System.out.println("We are sending a request for a certificate of the CA.");
            try {
                // Создаем сокет и подключаемся к серверу
                Socket caSocket = new Socket(caServerHostName, caPort);
                System.out.println("Connect to server " + caSocket.getRemoteSocketAddress());
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

                java.security.interfaces.RSAPublicKey rsaPublicKey =
                        (java.security.interfaces.RSAPublicKey) keyPair.getPublic();
                java.security.interfaces.RSAPrivateKey rsaPrivateKey =
                        (java.security.interfaces.RSAPrivateKey) keyPair.getPrivate();

                SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(rsaPublicKey.getEncoded());

                CertificationRequestInfo certificationRequestInfo =
                        new CertificationRequestInfo(ocspSubject, subjectPublicKeyInfo, null);

                // Создаем объект AlgorithmIdentifier из алгоритма подписи
                AlgorithmIdentifier algorithmIdentifier =
                        new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.1.1.11"), DERNull.INSTANCE);

                // Создаем подпись запроса на сертификат
                Signature signature = Signature.getInstance("SHA256withRSA");
                signature.initSign((PrivateKey) rsaPrivateKey);
                signature.update(certificationRequestInfo.getEncoded());
                byte[] signatureBytes = signature.sign();
                DERBitString derBitString = new DERBitString(signatureBytes);

                // Создаем объект CertificationRequest из CertificationRequestInfo, AlgorithmIdentifier и подписи
                CertificationRequest certificationRequest =
                        new CertificationRequest(certificationRequestInfo, algorithmIdentifier, derBitString);

                // Создаем PKCS#10 запрос на сертификат
                PKCS10CertificationRequest csr = new PKCS10CertificationRequest(certificationRequest);

                // Отправляем запрос на сервер
                out.writeInt(csr.getEncoded().length);
                out.write(csr.getEncoded());
                out.flush();
                System.out.println("The certificate request has been sent to the server");

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

                System.out.println("File saved, size: " + fileSize + " bytes");

                // Закрываем соединение
                caSocket.close();
                System.out.println("Connect with server closed");
            } catch (
                    ConnectException e) {
                System.out.println("Sorry, connection problems. " +
                        "The server may not be available right now.");
            } catch (
                    IOException e) {
                e.printStackTrace();
            } catch (
                    NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
                throw new RuntimeException(e);
            }
            ObjectOutputStream privateKeyToFile =
                    new ObjectOutputStream(new FileOutputStream(ocspServerResourcesPath + "privateKeyObj.dat"));
            privateKeyToFile.writeObject(ocsp.getPrivateKey());
            privateKeyToFile.close();

            try {
                try (ObjectInputStream keyCheck =
                             new ObjectInputStream(new FileInputStream(ocspServerResourcesPath + "privateKeyObj.dat"))) {
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
            try (ObjectInputStream keyCheck =
                         new ObjectInputStream(new FileInputStream(ocspServerResourcesPath + "privateKeyObj.dat"))) {
                ocspKey = (PrivateKey) keyCheck.readObject();
                ocsp.loadPrivateKey(ocspKey);
            } catch (IOException | ClassNotFoundException e) {
                System.out.println("Error loading private key: " + e.getMessage());
                System.exit(1);
            }
        }
    }
}
