package passkeyScanner;

import java.util.Map;
import java.util.Set;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)

public class AuthenticationResponse {
	
	private String type;
	private String id;
	private String rawId;
	private String authenticatorAttachment;
	private AuthenticatorAssertionResponseObject response;
	private Map<String, String> clientExtensionResults;
	private Set<String> transports;
	
	public AuthenticationResponse() {
		super();
	}
	
	public String getType() {
		return type;
	}
	
	public void setType(String type) {
		this.type = type;
	}
	
	public String getId() {
		return id;
	}
	
	public void setId(String id) {
		this.id = id;
	}
	
	public String getRawId() {
		return rawId;
	}
	
	public void setRawId(String rawId) {
		this.rawId = rawId;
	}
	
	public String getAuthenticatorAttachment() {
		return authenticatorAttachment;
	}
	
	public void setAuthenticatorAttachment(String authenticatorAttachment) {
		this.authenticatorAttachment = authenticatorAttachment;
	}
	
	public AuthenticatorAssertionResponseObject getResponse() {
		return response;
	}
	
	public void setResponse(AuthenticatorAssertionResponseObject response) {
		this.response = response;
	}
	
	public Map<String, String> getClientExtensionResults() {
		return clientExtensionResults;
	}
	
	public void setClientExtensionResults(Map<String, String> clientExtensionResults) {
		this.clientExtensionResults = clientExtensionResults;
	}
	
	public Set<String> getTransports() {
		return transports;
	}
	
	public void setTransports(Set<String> transports) {
		this.transports = transports;
	}
	
	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("\"AuthenticationResponse\": {\n  \"type\":\"");
		builder.append(type);
		builder.append("\",\n  \"id\":\"");
		builder.append(id);
		builder.append("\",\n  \"rawId\":\"");
		builder.append(rawId);
		builder.append("\",\n  \"authenticatorAttachment\":\"");
		builder.append(authenticatorAttachment);
		builder.append("\",\n  \"response\":");
		builder.append(response);
		builder.append(",\n  \"clientExtensionResults\":");
		builder.append(clientExtensionResults);
		builder.append(",\n  \"transports\":");
		builder.append(transports);
		builder.append("\n}\n");
		return builder.toString();
	}

}
