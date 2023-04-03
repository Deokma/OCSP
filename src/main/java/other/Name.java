package main.java.other;

/**
 * @author Denis Popolamov
 */
import java.util.List;

public class Name {
    private List<RelativeDistinguishedName> rdnSequence;

    public Name(List<RelativeDistinguishedName> rdnSequence) {
        this.rdnSequence = rdnSequence;
    }

    public List<RelativeDistinguishedName> getRdnSequence() {
        return rdnSequence;
    }

    public void setRdnSequence(List<RelativeDistinguishedName> rdnSequence) {
        this.rdnSequence = rdnSequence;
    }
}
