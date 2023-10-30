package passkeyScanner;

import java.util.Arrays;
import java.util.Base64;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public class PublicKeyCredentialCreationOptions {
	private String challenge;
	private Map<String, String> rp;
	private Map<String, String> user;
	private PubKeyCredParam[] pubKeyCredParams;
	private PubKeyCredDescriptor[] excludeCredentials;
	private AuthenticatorSelection authenticatorSelection;
	private int timeout;
	private String attestation;
	
	public PublicKeyCredentialCreationOptions(){
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
	
	public Map<String, String> getRp() {
		return rp;
	}
	
	public void setRp(Map<String, String> rp) {
		this.rp = rp;
	}
	
	public Map<String, String> getUser() {
		return user;
	}
	
	public void setUser(Map<String, String> user) {
		this.user = user;
	}
	
	public PubKeyCredParam[] getPubKeyCredParams() {
		return pubKeyCredParams;
	}
	
	public void setPubKeyCredParams(PubKeyCredParam[] pubKeyCredParams) {
		this.pubKeyCredParams = pubKeyCredParams;
	}
	
	public AuthenticatorSelection getAuthenticatorSelection() {
		return authenticatorSelection;
	}
	
	public void setAuthenticatorSelection(AuthenticatorSelection authenticatorSelection) {
		this.authenticatorSelection = authenticatorSelection;
	}
	
	public int getTimeout() {
		return timeout;
	}
	
	public void setTimeout(int timeout) {
		this.timeout = timeout;
	}
	
	public String getAttestation() {
		return attestation;
	}
	
	public PubKeyCredDescriptor[] getExcludeCredentials() {
		return excludeCredentials;
	}

	public void setExcludeCredentials(PubKeyCredDescriptor[] excludeCredentials) {
		this.excludeCredentials = excludeCredentials;
	}
	
	
	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("PublicKeyCredentialCreationOptions:{\n  \"challenge\":\"");
		builder.append(challenge);
		builder.append("\",\n  \"rp\":");
		builder.append(rp);
		builder.append(",\n  \"user\":");
		builder.append(user);
		builder.append(",\n  \"pubKeyCredParams\":");
		builder.append(Arrays.toString(pubKeyCredParams));
		builder.append(",\n  \"authenticatorSelection\":");
		builder.append(authenticatorSelection);
		builder.append(",\n  \"timeout\":");
		builder.append(timeout);
		builder.append(",\n  \"attestation\":\"");
		builder.append(attestation);
		builder.append("\"\n}\n");
		return builder.toString();
	}
	
	public void setAttestation(String attestation) {
		this.attestation = attestation;
	}

	

	
}
