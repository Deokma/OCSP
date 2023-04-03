package main.java.network;

import java.math.BigInteger;

/**
 * @author Denis Popolamov
 */
public class ExtensionAttribute {
    private BigInteger extensionAttributeType;
    private Object extensionAttributeValue;

    public ExtensionAttribute(BigInteger extensionAttributeType, Object extensionAttributeValue) {
        this.extensionAttributeType = extensionAttributeType;
        this.extensionAttributeValue = extensionAttributeValue;
    }

    public BigInteger getExtensionAttributeType() {
        return extensionAttributeType;
    }

    public Object getExtensionAttributeValue() {
        return extensionAttributeValue;
    }
}