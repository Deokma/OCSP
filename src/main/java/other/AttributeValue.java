package main.java.other;

/**
 * @author Denis Popolamov
 */
public class AttributeValue {
    private Object value;

    public AttributeValue(Object value) {
        this.value = value;
    }

    public Object getValue() {
        return value;
    }

    public void setValue(Object value) {
        this.value = value;
    }
}
