package main.java.other;

/**
 * @author Denis Popolamov
 */
import java.util.ArrayList;

public class RDNSequence {
    private ArrayList<RelativeDistinguishedName> rdnSequence = new ArrayList<>();

    public void addRDN(RelativeDistinguishedName rdn) {
        rdnSequence.add(rdn);
    }

    public ArrayList<RelativeDistinguishedName> getRDNSequence() {
        return rdnSequence;
    }
}
