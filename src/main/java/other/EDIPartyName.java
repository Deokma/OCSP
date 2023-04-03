package main.java.other;

/**
 * @author Denis Popolamov
 */
public class EDIPartyName {
    private String nameAssigner;
    private String partyName;

    public EDIPartyName(String partyName) {
        this.partyName = partyName;
    }

    public EDIPartyName(String nameAssigner, String partyName) {
        this.nameAssigner = nameAssigner;
        this.partyName = partyName;
    }

    public String getNameAssigner() {
        return nameAssigner;
    }

    public void setNameAssigner(String nameAssigner) {
        this.nameAssigner = nameAssigner;
    }

    public String getPartyName() {
        return partyName;
    }

    public void setPartyName(String partyName) {
        this.partyName = partyName;
    }
}
