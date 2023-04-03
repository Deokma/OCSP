package main.java.other;

import java.util.ArrayList;
import java.util.List;

public class Extensions {
    private final List<Extension> extensions = new ArrayList<>();

    public void addExtension(Extension extension) {
        extensions.add(extension);
    }

    public List<Extension> getExtensions() {
        return new ArrayList<>(extensions);
    }

    @Override
    public String toString() {
        return "Extensions{" +
                "extensions=" + extensions +
                '}';
    }
}
