package main.java.network;

/**
 * @author Denis Popolamov
 */
public class ORAddress {

    private BuiltlnStandardAttributes builtInStandardAttributes;
    private BuiltInDomainDefinedAttributes builtInDomainDefinedAttributes;
    private ExtensionAttributes extensionAttributes;

    public ORAddress(BuiltlnStandardAttributes builtInStandardAttributes,
                     BuiltInDomainDefinedAttributes builtInDomainDefinedAttributes,
                     ExtensionAttributes extensionAttributes) {
        this.builtInStandardAttributes = builtInStandardAttributes;
        this.builtInDomainDefinedAttributes = builtInDomainDefinedAttributes;
        this.extensionAttributes = extensionAttributes;
    }

    public BuiltlnStandardAttributes getBuiltInStandardAttributes() {
        return builtInStandardAttributes;
    }

    public BuiltInDomainDefinedAttributes getBuiltInDomainDefinedAttributes() {
        return builtInDomainDefinedAttributes;
    }

    public ExtensionAttributes getExtensionAttributes() {
        return extensionAttributes;
    }

    public void setBuiltInStandardAttributes(BuiltlnStandardAttributes builtInStandardAttributes) {
        this.builtInStandardAttributes = builtInStandardAttributes;
    }

    public void setBuiltInDomainDefinedAttributes(
            BuiltInDomainDefinedAttributes builtInDomainDefinedAttributes) {
        this.builtInDomainDefinedAttributes = builtInDomainDefinedAttributes;
    }

    public void setExtensionAttributes(ExtensionAttributes extensionAttributes) {
        this.extensionAttributes = extensionAttributes;
    }
}
