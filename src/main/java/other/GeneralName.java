package main.java.other;

import main.java.network.ORAddress;

/**
 * @author Denis Popolamov
 */
public class GeneralName {

    private OtherName otherName;
    private String rfc822Name;
    private String dnsName;
    private ORAddress x400Address;
    private Name directoryName;
    private EDIPartyName ediPartyName;
    private String uniformResourceIdentifier;
    private byte[] ipAddress;
    private String registeredID;

    public GeneralName(OtherName otherName) {
        this.otherName = otherName;
    }

    public GeneralName(String rfc822Name) {
        this.rfc822Name = rfc822Name;
    }

    public GeneralName(ORAddress x400Address) {
        this.x400Address = x400Address;
    }

    public GeneralName(Name directoryName) {
        this.directoryName = directoryName;
    }

    public GeneralName(EDIPartyName ediPartyName) {
        this.ediPartyName = ediPartyName;
    }

    public GeneralName(byte[] ipAddress) {
        this.ipAddress = ipAddress;
    }

    public GeneralName(String registeredID, boolean isRegisteredID) {
        if (isRegisteredID) {
            this.registeredID = registeredID;
        }
    }

    public OtherName getOtherName() {
        return otherName;
    }

    public String getRfc822Name() {
        return rfc822Name;
    }

    public String getDnsName() {
        return dnsName;
    }

    public ORAddress getX400Address() {
        return x400Address;
    }

    public Name getDirectoryName() {
        return directoryName;
    }

    public EDIPartyName getEdiPartyName() {
        return ediPartyName;
    }

    public String getUniformResourceIdentifier() {
        return uniformResourceIdentifier;
    }

    public byte[] getIpAddress() {
        return ipAddress;
    }

    public String getRegisteredID() {
        return registeredID;
    }
}
