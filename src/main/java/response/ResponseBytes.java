package main.java.response;

/**
 * @author Denis Popolamov
 */
public class ResponseBytes {
    private final String responseType;
    private final byte[] response;

    public ResponseBytes(String responseType, byte[] response) {
        this.responseType = responseType;
        this.response = response;
    }

    public String getResponseType() {
        return responseType;
    }

    public byte[] getResponse() {
        return response;
    }
}
