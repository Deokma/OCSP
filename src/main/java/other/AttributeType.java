package main.java.other;

/**
 * @author Denis Popolamov
 */
import java.io.IOException;
import java.util.Arrays;

public class AttributeType {
    private int[] oid;

    public AttributeType(int[] oid) {
        this.oid = oid;
    }

    public int[] getOid() {
        return oid;
    }

    public void setOid(int[] oid) {
        this.oid = oid;
    }

    @Override
    public String toString() {
        return Arrays.toString(oid);
    }

    public byte[] encode() throws IOException {
        int length = oid.length;
        if (length < 1) {
            throw new IOException("OID cannot be empty.");
        }

        byte[] encoded = new byte[length];
        encoded[0] = (byte) (oid[0] * 40 + oid[1]);

        for (int i = 2; i < length; i++) {
            int val = oid[i];
            int pos = encoded.length - 1;
            while (val > 0) {
                encoded[pos--] = (byte) ((val & 0x7F) | 0x80);
                val >>>= 7;
            }
            encoded[pos] = (byte) (encoded[pos] & 0x7F);
        }

        return encoded;
    }

    public static AttributeType decode(byte[] encoded) throws IOException {
        int length = encoded.length;
        if (length < 1) {
            throw new IOException("Cannot decode empty byte array.");
        }

        int[] oid = new int[length];
        int idx = 0;

        int val = encoded[idx++] & 0xFF;
        oid[0] = val / 40;
        oid[1] = val % 40;

        while (idx < length) {
            val = encoded[idx++] & 0xFF;
            int value = val & 0x7F;
            while ((val & 0x80) == 0x80) {
                value <<= 7;
                val = encoded[idx++] & 0xFF;
                value |= val & 0x7F;
            }
            oid[idx] = value;
        }

        return new AttributeType(oid);
    }
}
