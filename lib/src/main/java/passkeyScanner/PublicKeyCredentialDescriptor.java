package passkeyScanner;

import java.util.Arrays;

public class PublicKeyCredentialDescriptor {

	private String type;
	private String id;
	private String[] transports;

	public PublicKeyCredentialDescriptor() {
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

	public String[] getTransports() {
		return transports;
	}

	public void setTransports(String[] transports) {
		this.transports = transports;
	}

	@Override
	public String toString() {
		return "\"PublicKeyCredentialDescriptor\":\n  {\"type\":\"" + type + "\",\n  \"id\":\"" + id + "\",\n  \"transports\":"
				+ Arrays.toString(transports) + "\n}";
	}
}
