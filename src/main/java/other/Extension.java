package main.java.other;

import java.math.BigInteger;

public class Extension {
    private final String extnID;
    private final boolean critical;
    private final byte[] extnValue;

    public Extension(String extnID, boolean critical, byte[] extnValue) {
        this.extnID = extnID;
        this.critical = critical;
        this.extnValue = extnValue.clone();
    }

    public String getExtnID() {
        return extnID;
    }

    public boolean isCritical() {
        return critical;
    }

    public byte[] getExtnValue() {
        return extnValue.clone();
    }

    @Override
    public String toString() {
        return "Extension{" +
                "extnID='" + extnID + '\'' +
                ", critical=" + critical +
                ", extnValue=" + new BigInteger(1, extnValue).toString(16) +
                '}';
    }
}
