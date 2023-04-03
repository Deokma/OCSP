package main.java.network.atributes;


/**
 * @author Denis Popolamov
 */
public class NetworkAddress {
    private String address;

    public NetworkAddress(String address) {
        this.address = address;
    }

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }

    @Override
    public String toString() {
        return "NetworkAddress: " + address.toString();
    }
}
