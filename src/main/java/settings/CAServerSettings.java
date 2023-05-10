package settings;

import model.CertificateAuthority;

import java.io.*;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Properties;
import java.util.Scanner;

public class CAServerSettings extends Settings {


    /*public CAServerSettings() throws IOException {
        Properties prop = readPropertiesFile();

    }*/

    public static void checkCAServerNameFile() throws IOException, ClassNotFoundException {
        readPropertiesFile();
        new File(caServerResourcesPath).mkdirs();
        new File(caServerPath).mkdirs();
        new File(caCertificatesPath).mkdirs();
        new File(caServerKeysPath).mkdirs();
        if (!new File(caServerResourcesPath + "caName.dat").exists()) {
            System.out.print("Enter name of your CA server: ");
            Scanner in = new Scanner(System.in);
            String caNameInput = in.nextLine();
            ObjectOutputStream caNameFileOutput =
                    new ObjectOutputStream(new FileOutputStream(caServerResourcesPath + "caName.dat"));
            caNameFileOutput.writeObject(caNameInput);
            caNameFileOutput.close();

            ObjectInputStream caNameFileInput =
                    new ObjectInputStream(new FileInputStream(caServerResourcesPath + "caName.dat"));
            caServerName = (String) caNameFileInput.readObject();
        } else {
            try {
                ObjectInputStream caNameFileInput =
                        new ObjectInputStream(new FileInputStream(caServerResourcesPath + "caName.dat"));
                caServerName = (String) caNameFileInput.readObject();
            } catch (Exception e) {
                System.out.println("An error occurred while getting the name of the CA");
            }
        }
    }

    public static void checkCAServerStartConfigure(CertificateAuthority ca, PrivateKey caKey) {
        if (!new File(caServerPath + "caCert.crt").exists()) {
            System.out.println("Create caCert.crt.");
            try {
                // Создание само подписанного сертификата
                X509Certificate selfSignedCert = ca.createSelfSignedCertificate(new Date(),
                        new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000L));
                FileOutputStream caCertFile = new FileOutputStream(caServerPath + "caCert.crt");
                caCertFile.write(selfSignedCert.getEncoded());
                caCertFile.close();
                FileOutputStream caPublicKeyFile = new FileOutputStream(caServerPath + "caPublicKey.key");
                caPublicKeyFile.write(selfSignedCert.getPublicKey().getEncoded());
                caPublicKeyFile.close();
                FileOutputStream caPrivateKeyFile = new FileOutputStream(caServerPath + "caPrivateKey.key");
                caPrivateKeyFile.write(ca.getPrivateKey().getEncoded());
                caPrivateKeyFile.close();
                ObjectOutputStream privateKeyToFile =
                        new ObjectOutputStream(new FileOutputStream(caServerResourcesPath + "privateKeyObj.dat"));
                privateKeyToFile.writeObject(ca.getPrivateKey());
                privateKeyToFile.close();
                try (ObjectInputStream keyCheck =
                             new ObjectInputStream(new FileInputStream(caServerResourcesPath + "privateKeyObj.dat"))) {
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
            try (ObjectInputStream keyCheck =
                         new ObjectInputStream(new FileInputStream(caServerResourcesPath + "privateKeyObj.dat"))) {
                caKey = (PrivateKey) keyCheck.readObject();
                ca.loadPrivateKey(caKey);
            } catch (IOException | ClassNotFoundException e) {
                System.out.println("Error loading private key: " + e.getMessage());
                System.exit(1);
            }
        }
    }
}
