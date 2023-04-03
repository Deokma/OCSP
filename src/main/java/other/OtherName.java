package main.java.other;

/**
 * @author Denis Popolamov
 */
public class OtherName {

    private String typeID;
    private Object value;

    public OtherName(String typeID, Object value) {
        this.typeID = typeID;
        this.value = value;
    }

    public String getTypeID() {
        return typeID;
    }

    public Object getValue() {
        return value;
    }

    public void setTypeID(String typeID) {
        this.typeID = typeID;
    }

    public void setValue(Object value) {
        this.value = value;
    }
}
