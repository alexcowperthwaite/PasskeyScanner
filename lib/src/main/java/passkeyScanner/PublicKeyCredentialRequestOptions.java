package passkeyScanner;

import java.util.Arrays;
import java.util.Base64;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public class PublicKeyCredentialRequestOptions {
	private String challenge;
	private int timeout;
	private String rpId;
	private PublicKeyCredentialDescriptor[] allowCredentials;
	private String userVerification;
	private String attestation;
	private String[] attestationFormats;
	private Map<String, String> extensions;
	
	public PublicKeyCredentialRequestOptions() {
		super();
	}
	
	public String getChallenge() {
		return challenge;
	}
	
	public byte[] getDecodedChallenge() {
		byte[] b = null;
		if ((b = tryDecodeBase64()) == null) {
			return this.getChallenge().getBytes();
		}
		else {
			return b;
		}
	}
	
	public byte[] tryDecodeBase64() {
		try {
			return Base64.getDecoder().decode(this.challenge);
		}
		catch(IllegalArgumentException e) {
			return null;
		}
	}
	
	public void setChallenge(String challenge) {
		this.challenge = challenge;
	}
	
	public int getTimeout() {
		return timeout;
	}
	
	public void setTimeout(int timeout) {
		this.timeout = timeout;
	}
	
	public String getRpId() {
		return rpId;
	}
	
	public void setRpId(String rpId) {
		this.rpId = rpId;
	}
	
	public PublicKeyCredentialDescriptor[] getAllowCredentials() {
		return allowCredentials;
	}
	
	public void setAllowCredentials(PublicKeyCredentialDescriptor[] allowCredentials) {
		this.allowCredentials = allowCredentials;
	}
	
	public String getUserVerification() {
		return userVerification;
	}
	
	public void setUserVerification(String userVerification) {
		this.userVerification = userVerification;
	}
	
	public String getAttestation() {
		return attestation;
	}
	
	public void setAttestation(String attestation) {
		this.attestation = attestation;
	}

	public String[] getAttestationFormats() {
		return attestationFormats;
	}
	
	public void setAttestationFormats(String[] attestationFormats) {
		this.attestationFormats = attestationFormats;
	}
	
	public Map<String, String> getExtensions() {
		return extensions;
	}
	
	public void setExtensions(Map<String, String> extensions) {
		this.extensions = extensions;
	}
	
	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("PublicKeyCredentialRequestOptions:{\n  \"challenge\":\"");
		builder.append(challenge);
		builder.append("\",\n  \"timeout\":");
		builder.append(timeout);
		builder.append(",\n  \"rpId\":\"");
		builder.append(rpId);
		builder.append("\",\n  \"allowCredentials\":");
		builder.append(Arrays.toString(allowCredentials));
		builder.append(",\n  \"userVerification\":\"");
		builder.append(userVerification);
		builder.append("\",\n  \"attestation\":\"");
		builder.append(attestation);
		builder.append("\",\n  \"attestationFormats\":");
		builder.append(Arrays.toString(attestationFormats));
		builder.append(",\n  \"extensions\":");
		builder.append(extensions);
		builder.append("\n}\n");
		return builder.toString();
	}

}
