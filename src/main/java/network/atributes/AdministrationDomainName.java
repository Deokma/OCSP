package main.java.network.atributes;

import java.math.BigInteger;

public class AdministrationDomainName {
    private BigInteger numeric;
    private String printable;

    public AdministrationDomainName(BigInteger numeric, String printable) {
        this.numeric = numeric;
        this.printable = printable;
    }

    public BigInteger getNumeric() {
        return numeric;
    }

    public void setNumeric(BigInteger numeric) {
        this.numeric = numeric;
    }

    public String getPrintable() {
        return printable;
    }

    public void setPrintable(String printable) {
        this.printable = printable;
    }
}