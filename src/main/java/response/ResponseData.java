package main.java.response;

/**
 * @author Denis Popolamov
 */
import main.java.other.Extensions;
import main.java.other.Version;

import java.util.List;
import java.time.LocalDateTime;

public class ResponseData {
    private Version version; // Default value is 1
    private ResponderID responderID;
    private LocalDateTime producedAt;
    private List<SingleResponse> responses;
    private Extensions responseExtensions;

    public ResponseData(ResponderID responderID, LocalDateTime producedAt, List<SingleResponse> responses) {
        this.responderID = responderID;
        this.producedAt = producedAt;
        this.responses = responses;
    }

    public void setVersion(Version version) {
        this.version = version;
    }

    public void setResponseExtensions(Extensions responseExtensions) {
        this.responseExtensions = responseExtensions;
    }

    // Getters for all fields
    public int getVersion() {
        Version v = new Version(0);
        return v.getValue();
    }

    public ResponderID getResponderID() {
        return responderID;
    }

    public LocalDateTime getProducedAt() {
        return producedAt;
    }

    public List<SingleResponse> getResponses() {
        return responses;
    }

    public Extensions getResponseExtensions() {
        return responseExtensions;
    }
}
