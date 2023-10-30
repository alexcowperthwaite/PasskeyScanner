package passkeyScanner;

import java.util.Arrays;
import java.util.Base64;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.AttestationObject;
@JsonIgnoreProperties(ignoreUnknown = true)

public class AuthenticatorAttestationResponseObject {
	private String clientDataJSON;
	private String attestationObject;
	private String[] transports;
	private int publicKeyAlgorithm;
	private String publicKey;
	private String authenticatorData;
	
	public AuthenticatorAttestationResponseObject() {
		super();
	}

	public String getClientDataJSON() {
		return clientDataJSON;
	}

	public void setClientDataJSON(String clientDataJSON) {
		this.clientDataJSON = clientDataJSON;
	}

	public String getAttestationObject() {
		return attestationObject;
	}

	public AttestationObject decodeAttestationObject() {
		AttestationObject attestObj = null;
		byte[] cborArray = Base64.getUrlDecoder().decode(attestationObject);
	
        // Check if the attestationObject value is empty
        if (cborArray != null && cborArray.length > 0) {
            // Ensure the out is propery indented
            ObjectMapper objectMapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
            ObjectConverter objectConverter = new ObjectConverter(objectMapper, new ObjectMapper(new CBORFactory()));
            CborConverter cborConverter = objectConverter.getCborConverter();
            // Decode the CBOR using a library
            attestObj = cborConverter.readValue(cborArray, AttestationObject.class);  
        }
        
        return attestObj;
	}
	
	public void setAttestationObject(String attestationObject) {
		this.attestationObject = attestationObject;
	}

	public String[] getTransports() {
		return transports;
	}

	public void setTransports(String[] transports) {
		this.transports = transports;
	}

	public int getPublicKeyAlgorithm() {
		return publicKeyAlgorithm;
	}

	public void setPublicKeyAlgorithm(int publicKeyAlgorithm) {
		this.publicKeyAlgorithm = publicKeyAlgorithm;
	}

	public String getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(String publicKey) {
		this.publicKey = publicKey;
	}

	public String getAuthenticatorData() {
		return authenticatorData;
	}

	public void setAuthenticatorData(String authenticatorData) {
		this.authenticatorData = authenticatorData;
	}
	
    public static String getDecodedAttestObjectArray(byte[] cborArray) {
        // Check if the attestationObject value is empty
        if (cborArray != null && cborArray.length > 0) {
            // Ensure the out is propery indented
            ObjectMapper objectMapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
            ObjectConverter objectConverter = new ObjectConverter(objectMapper, new ObjectMapper(new CBORFactory()));
            CborConverter cborConverter = objectConverter.getCborConverter();
            // Decode the CBOR using a library
            AttestationObject attestObj = cborConverter.readValue(cborArray, AttestationObject.class);        
            JsonConverter jsonConverter = objectConverter.getJsonConverter();
            String decodedAttestObjArray = jsonConverter.writeValueAsString(attestObj);
            return decodedAttestObjArray;
        }
        // Return error message when valid attestationObject CBOR data is not found
        return "FAIL";
    }
    
    public static String getDecodedAttestObjectArray(String cborArray) {
    	return getDecodedAttestObjectArray(Base64.getUrlDecoder().decode(cborArray));
    }

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("{\n  \"clientDataJSON\":");
		builder.append(clientDataJSON);
		builder.append(",\n  \"attestationObject\":");
		builder.append(getDecodedAttestObjectArray(attestationObject));
		builder.append(",\n  \"transports\":");
		builder.append(Arrays.toString(transports));
		builder.append(",\n  \"publicKeyAlgorithm\":");
		builder.append(publicKeyAlgorithm);
		builder.append(",\n  \"publicKey\":");
		builder.append(publicKey);
		builder.append(",\n  \"authenticatorData\":");
		builder.append(authenticatorData);
		builder.append("\n}");
		return builder.toString();
	}

}
