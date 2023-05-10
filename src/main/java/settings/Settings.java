package settings;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class Settings {
    static String ocspServerResourcesPath;
    static String ocspName;
    static String ocspServerPath;
    static String caServerHostName;
    static int caPort;
    static String ocspClientPath;
    static String ocspClientResourcesPath;
    static String clientName;
    static String certificatesPath;
    static String caServerResourcesPath;
    static String caServerName;
    static String caServerPath;
    static String caCertificatesPath;
    static String caServerKeysPath;
    static String caClientName;
    static String caClientResourcesPath;
    static String caClientPath;

    public static void readPropertiesFile() throws IOException {
        Properties prop = new Properties();
        InputStream input = new FileInputStream("src/main/resources/settings.properties");
        prop.load(input);
        caClientResourcesPath = prop.getProperty("caClientResourcesPath");
        caClientPath = prop.getProperty("caClientPath");
        caServerResourcesPath = prop.getProperty("caServerResourcesPath");
        caServerPath = prop.getProperty("caServerPath");
        caCertificatesPath = prop.getProperty("caCertificatesPath");
        caServerKeysPath = prop.getProperty("caServerKeysPath");
        ocspClientResourcesPath = prop.getProperty("ocspClientResourcesPath");
        caServerHostName = prop.getProperty("caServerHostName");
        caPort = Integer.parseInt(prop.getProperty("caPort"));
        ocspClientPath = prop.getProperty("ocspClientPath");
        certificatesPath = prop.getProperty("certificatesPath");
        ocspServerResourcesPath = prop.getProperty("ocspServerResourcesPath");
        caServerHostName = prop.getProperty("caServerHostName");
        caPort = Integer.parseInt(prop.getProperty("caPort"));
        ocspServerPath = prop.getProperty("ocspServerPath");

    }
}
