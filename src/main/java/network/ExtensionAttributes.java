package main.java.network;

import java.util.Set;

public class ExtensionAttributes {
    private Set<ExtensionAttribute> extensionAttributes;

    public ExtensionAttributes(Set<ExtensionAttribute> extensionAttributes) {
        this.extensionAttributes = extensionAttributes;
    }

    public Set<ExtensionAttribute> getExtensionAttributes() {
        return extensionAttributes;
    }
}