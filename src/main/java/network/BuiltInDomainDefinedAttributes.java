package main.java.network;

/**
 * @author Denis Popolamov
 */

import java.util.List;

public class BuiltInDomainDefinedAttributes {
    private List<BuiltlnDomainDefinedAttribute> attributes;

    public BuiltInDomainDefinedAttributes(List<BuiltlnDomainDefinedAttribute> attributes) {
        this.attributes = attributes;
    }

    public List<BuiltlnDomainDefinedAttribute> getAttributes() {
        return attributes;
    }

    public void setAttributes(List<BuiltlnDomainDefinedAttribute> attributes) {
        this.attributes = attributes;
    }
}