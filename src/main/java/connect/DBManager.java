package connect;

import org.bouncycastle.cert.ocsp.CertificateID;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.sql.*;
import java.util.Properties;

/**
 * Класс для взаимодействия с базой данных
 */
public class DBManager {
    private Connection conn;

    /**
     * Конструктор класса для создания подключения к базе данных
     */
    public DBManager() {
        try {
            Class.forName("org.postgresql.Driver");
            Properties props = new Properties();
            InputStream input = new FileInputStream("src/main/resources/database.properties");
            props.load(input);
            String url = props.getProperty("url");
            String user = props.getProperty("user");
            String password = props.getProperty("password");
            conn = DriverManager.getConnection(url, user, password);
        } catch (ClassNotFoundException | SQLException | IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Добавление данный о сертификате в базу данных
     * @param certID certificateID
     * @param certificate сам сертификат (не используется)
     * @param startDate Дата подписания сертификата
     * @param endDate Дата окончания годности сертификата
     * @param status Статус сертификата (по умолчания GOOD)
     * @throws CertificateEncodingException
     * @throws IOException
     */
    public void addCertificate(CertificateID certID, X509Certificate certificate,
                               java.util.Date startDate, java.util.Date endDate, String status) throws CertificateEncodingException, IOException {
        try {
            PreparedStatement ps = conn.prepareStatement("INSERT INTO certificates " +
                    "(cert_id,certificate_data, cert_start_date,cert_end_date,cert_status) VALUES " +
                    "(?, ?, ?, ?,?)");
            byte[] certIdBytes = certID.toASN1Primitive().getEncoded();
            ps.setBytes(1, certIdBytes);
            ps.setBytes(2, certificate.getEncoded());
            ps.setDate(3, new java.sql.Date(startDate.getTime()));
            ps.setDate(4, new java.sql.Date(endDate.getTime()));
            ps.setString(5, status);

            ps.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    /**
     * Проверка на наличие сертификата
     * @param certificateID certificateID
     * @return true если присутствует, false если нет
     */
    public Boolean certExist(CertificateID certificateID) {
        try {
            byte[] certIdBytes = certificateID.toASN1Primitive().getEncoded();

            PreparedStatement ps = conn.prepareStatement("SELECT EXISTS (SELECT 1 FROM certificates WHERE cert_id = ?)");
            ps.setBytes(1, certIdBytes);

            ResultSet rs = ps.executeQuery();
            rs.next();
            return rs.getBoolean(1);
        } catch (SQLException | IOException ex) {
            ex.printStackTrace();
            return false;
        }
    }

    /**
     * Получить статус сертификата по certificateID
     * @param certificateID certificateID
     * @return статус (null если статуса нет)
     */
    public String getCertStatusByCertId(CertificateID certificateID) {
        try {
            byte[] certIdBytes = certificateID.toASN1Primitive().getEncoded();

            PreparedStatement ps = conn.prepareStatement("SELECT cert_status FROM certificates WHERE cert_id = ?");
            ps.setBytes(1, certIdBytes);

            ResultSet rs = ps.executeQuery();

            if (rs.next()) {
                String certStatus = rs.getString("cert_status");
                return certStatus;
            }
        } catch (SQLException ex) {
            ex.printStackTrace();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return null; // Устанавливается на unknown в дальнейшем
    }


}
