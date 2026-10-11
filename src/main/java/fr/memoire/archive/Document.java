package fr.memoire.archive;

import java.util.Arrays;
import java.util.Objects;

public record Document(Metadata metadata, byte[] content) {

    public Document {
        Objects.requireNonNull(metadata, "Metadata cannot be null");
        Objects.requireNonNull(content, "Content cannot be null");
        content = content.clone();
    }

    @Override
    public byte[] content() {
        return content.clone();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Document other)) return false;
        return Objects.equals(metadata, other.metadata)
                && Arrays.equals(content, other.content);
    }

    @Override
    public int hashCode() {
        return Objects.hash(metadata, Arrays.hashCode(content));
    }

    @Override
    public String toString() {
        return "Document[metadata=" + metadata + ", contentLength=" + content.length + " bytes]";
    }
}