package main.java.other;

/**
 * @author Denis Popolamov
 */
public class AttributeTypeAndValue {
private AttributeType type;
private AttributeValue Value;

    public AttributeTypeAndValue(AttributeType type, AttributeValue value) {
        this.type = type;
        Value = value;
    }

    public AttributeType getType() {
        return type;
    }

    public void setType(AttributeType type) {
        this.type = type;
    }

    public AttributeValue getValue() {
        return Value;
    }

    public void setValue(AttributeValue value) {
        Value = value;
    }
}
