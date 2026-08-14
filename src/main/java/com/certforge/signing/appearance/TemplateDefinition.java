package com.certforge.signing.appearance;

import java.util.Objects;

public class TemplateDefinition {
    private final String name;
    private final SignatureAppearance appearance;

    public TemplateDefinition(String name, SignatureAppearance appearance) {
        this.name = Objects.requireNonNull(name, "name cannot be null");
        this.appearance = Objects.requireNonNull(appearance, "appearance cannot be null");
    }

    public String name() {
        return name;
    }

    public SignatureAppearance appearance() {
        return appearance;
    }
}
