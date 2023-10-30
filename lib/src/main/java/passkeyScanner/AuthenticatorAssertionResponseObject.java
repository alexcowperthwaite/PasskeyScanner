package passkeyScanner;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.webauthn4j.converter.AuthenticatorDataConverter;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput;
@JsonIgnoreProperties(ignoreUnknown = true)

public class AuthenticatorAssertionResponseObject {

	private String clientDataJSON;
	private String authenticatorData;
	private String signature;
	private String userHandle;
	
	public AuthenticatorAssertionResponseObject() {
		super();
	}

	public String getClientDataJSON() {
		return clientDataJSON;
	}

	public void setClientDataJSON(String clientDataJSON) {
		this.clientDataJSON = clientDataJSON;
	}

	public String getAuthenticatorData() {
		return authenticatorData;
	}

	public void setAuthenticatorData(String authenticatorData) {
		this.authenticatorData = authenticatorData;
	}
	
	public AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> decodeAuthenticatorData() {
		AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> ad = null;
		byte[] cborArray = Base64.getUrlDecoder().decode(authenticatorData);
		
        if (cborArray != null && cborArray.length > 0) {
            // Ensure the out is property indented
            ObjectMapper objectMapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
            ObjectConverter objectConverter = new ObjectConverter(objectMapper, new ObjectMapper(new CBORFactory()));
            AuthenticatorDataConverter adc = new AuthenticatorDataConverter(objectConverter);
            ad = adc.convert(cborArray);
        }
		
		return ad;
	}

	public String getSignature() {
		return signature;
	}

	public void setSignature(String signature) {
		this.signature = signature;
	}

	public String getUserHandle() {
		return userHandle;
	}

	public void setUserHandle(String userHandle) {
		this.userHandle = userHandle;
	}
	
	public static String getDecodedAuthenticatorData(byte[] cborArray) {
    		
        // Check if the AuthenticatorData Object value is empty
        if (cborArray != null && cborArray.length > 0) {
            // Ensure the out is property indented
            ObjectMapper objectMapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
            ObjectConverter objectConverter = new ObjectConverter(objectMapper, new ObjectMapper(new CBORFactory()));
            AuthenticatorDataConverter adc = new AuthenticatorDataConverter(objectConverter);
            AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> ad = adc.convert(cborArray);
   
            JsonConverter jsonConverter = objectConverter.getJsonConverter();
            String decodedAthenticatorData = jsonConverter.writeValueAsString(ad);
            return decodedAthenticatorData;
        }
        // Return error message when valid attestationObject CBOR data is not found
        return "FAIL";
	}
	
    public static String getDecodedAuthenticatorData(String cborArray) {
    	return getDecodedAuthenticatorData(Base64.getUrlDecoder().decode(cborArray));
    }

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("{\n  \"clientDataJSON\": ");
		builder.append(new String(Base64.getUrlDecoder().decode(clientDataJSON), StandardCharsets.UTF_8));
		builder.append(",\n    \"authenticatorData\":\n");
		builder.append(getDecodedAuthenticatorData(authenticatorData));
		builder.append(",\n    \"signature\":\"");
		builder.append(signature);
		builder.append("\",\n    \"userHandle\":\"");
		builder.append(userHandle);
		builder.append("\"\n  }");
		return builder.toString();
	}
}
