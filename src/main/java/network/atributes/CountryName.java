package main.java.network.atributes;

import java.math.BigInteger;

public class CountryName {
    private static final int UB_COUNTRY_NAME_NUMERIC_LENGTH = 3;
    private static final int UB_COUNTRY_NAME_ALPHA_LENGTH = 2;

    private BigInteger dccCode;
    private String alpha2Code;

    public CountryName(BigInteger dccCode, String alpha2Code) {
        if (dccCode != null) {
            if (dccCode.bitLength() > UB_COUNTRY_NAME_NUMERIC_LENGTH * 8) {
                throw new IllegalArgumentException(
                        "DCC code too long (max " + UB_COUNTRY_NAME_NUMERIC_LENGTH + " bytes)");
            }
        }
        if (alpha2Code != null) {
            if (alpha2Code.length() > UB_COUNTRY_NAME_ALPHA_LENGTH) {
                throw new IllegalArgumentException(
                        "Alpha-2 code too long (max " + UB_COUNTRY_NAME_ALPHA_LENGTH + " characters)");
            }
        }
        this.dccCode = dccCode;
        this.alpha2Code = alpha2Code;
    }

    public BigInteger getDccCode() {
        return dccCode;
    }

    public String getAlpha2Code() {
        return alpha2Code;
    }

    @Override
    public String toString() {
        if (dccCode != null) {
            return "xl21-dcc-code: " + dccCode.toString();
        } else {
            return "iso-3166-alpha2-code: " + alpha2Code;
        }
    }
}
