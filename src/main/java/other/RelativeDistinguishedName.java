package main.java.other;

/**
 * @author Denis Popolamov
 */
import java.util.List;

public class RelativeDistinguishedName {
    private List<AttributeTypeAndValue> attributeTypeAndValues;

    public RelativeDistinguishedName(List<AttributeTypeAndValue> attributeTypeAndValues) {
        this.attributeTypeAndValues = attributeTypeAndValues;
    }

    public List<AttributeTypeAndValue> getAttributeTypeAndValues() {
        return attributeTypeAndValues;
    }

    public void setAttributeTypeAndValues(List<AttributeTypeAndValue> attributeTypeAndValues) {
        this.attributeTypeAndValues = attributeTypeAndValues;
    }
}
