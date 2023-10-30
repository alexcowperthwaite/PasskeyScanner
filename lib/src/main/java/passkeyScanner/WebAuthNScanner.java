package passkeyScanner;
import static burp.api.montoya.scanner.ConsolidationAction.KEEP_BOTH;
import static burp.api.montoya.scanner.ConsolidationAction.KEEP_EXISTING;

import java.util.Arrays;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

public class WebAuthNScanner implements ScanCheck {

	//https://w3c.github.io/webauthn/#dictdef-publickeycredentialcreationoptionsjson
	private static final String[] publicKeyCredentialCreationOptions = {"rp", "user", "challenge", "pubKeyCredParams", "timeout"};
	//https://w3c.github.io/webauthn/#dictdef-registrationresponsejson
	private static final String[] authenticatorAttestationResponse = {"id", "rawId", "response", "attestationObject", "authenticatorAttachment", "clientExtensionResults", "type"};
	//https://w3c.github.io/webauthn/#dictdef-publickeycredentialrequestoptions
	private static final String[] publicKeyCredentialRequestOptions = {"challenge", "timeout", "rpId"};
	//https://w3c.github.io/webauthn/#iface-authenticatorresponse
	private static final String[] authenticatorAssertionResponse = {"id", "rawId", "response", "authenticatorData", "signature", "authenticatorAttachment", "clientExtensionResults", "type"};

	private final MontoyaApi api;
	private Logging logger; 
	private Scanner scanner;
	@JsonIgnoreProperties(ignoreUnknown = true)
	
	WebAuthNScanner(MontoyaApi api, Logging logger){
		this.api = api;
		this.logger = logger;
		this.scanner = new Scanner(logger);
	}
	
	@Override
	public AuditResult activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint) {
		return null;
	}

	@Override
	public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse) {
		
		String resp = baseRequestResponse.response().bodyToString();
		String req = baseRequestResponse.request().bodyToString();
		
		String mime = baseRequestResponse.response().statedMimeType().toString();
		if(!mime.toLowerCase().contains("json")) {
			logger.logToError("type error");
			return scanner.getFindings();
		}				
		
		if (isPublicKeyCredentialCreationOptions(resp)) {
			//logger.logToOutput("Matched public key credential registration options");
			PublicKeyCredentialCreationOptions pkcco = findPublicKeyCredentialCreationOptions(resp);
			logger.logToOutput(pkcco.toString());
			scanner.scanPubKeyCredCreationOptions(baseRequestResponse, pkcco);

			//com.webauthn4j.data.PublicKeyCredentialCreationOptions pkcco = om.readValue(resp, com.webauthn4j.data.PublicKeyCredentialCreationOptions.class);
		}
		if (isAuthenticatorAttestationResponse(req)) {
			//logger.logToOutput("Matched authenticator registration/attestation");
			RegistrationResponse rr = findRegistrationResponse(req);
			logger.logToOutput(rr.toString());
			scanner.scanRegistrationResponse(baseRequestResponse, rr);
			
		}
		if (isPublicKeyCredentialRequestOptions(resp)) {
			//logger.logToOutput("Matched public key credential request options");
			PublicKeyCredentialRequestOptions pkcro = findPublicKeyCredentialRequestOptions(resp);
			logger.logToOutput(pkcro.toString());
			scanner.scanPubKeyCredRequestOptions(baseRequestResponse, pkcro);
			
		}
		if (isAuthenticatorAssertionResponse(req)) {
			//logger.logToOutput("Matched authenticator authenticate/assertion");
			AuthenticationResponse ar = findAuthenticationResponse(req);
			logger.logToOutput(ar.toString());
			scanner.scanAuthenticationResponse(baseRequestResponse, ar);

		}
		return scanner.getFindings();
	}

	@Override
	public ConsolidationAction consolidateIssues(AuditIssue newIssue, AuditIssue existingIssue) {
		return existingIssue.detail().equals(newIssue.detail()) ? KEEP_EXISTING : KEEP_BOTH;
	}

	private boolean isPublicKeyCredentialCreationOptions(String response) {
		boolean x = Arrays.stream(publicKeyCredentialCreationOptions).allMatch(response::contains);
		//logger.logToOutput("pub key cred options: " + x);
		return x;
	}
	
	private PublicKeyCredentialCreationOptions findPublicKeyCredentialCreationOptions(String response) {
		ObjectMapper om = new ObjectMapper();
		try {
			JsonNode jt = om.readTree(response);
			JsonNode rootNode = jt.findParent(publicKeyCredentialCreationOptions[3]);
			if (rootNode == null) {
				return null;
			}
			if(rootNode.has(publicKeyCredentialCreationOptions[0]) && rootNode.has(publicKeyCredentialCreationOptions[1]) && rootNode.has(publicKeyCredentialCreationOptions[2])) {
				logger.logToOutput("Found public key credential options: ");
				PublicKeyCredentialCreationOptions pkcco = om.treeToValue(rootNode, PublicKeyCredentialCreationOptions.class);
				return pkcco;
			}
			
		} catch (JsonProcessingException e) {
			logger.logToError(e.getMessage());
		}
		return null;
	}
	
	private boolean isAuthenticatorAttestationResponse(String request) {
		boolean x = Arrays.stream(authenticatorAttestationResponse).allMatch(request::contains);
		//logger.logToOutput("attestation response: " + x);
		return x;
	}
	
	private RegistrationResponse findRegistrationResponse(String request) {
		ObjectMapper om = new ObjectMapper();
		try {
			JsonNode jt = om.readTree(request);
			JsonNode rootNode = jt.findParent(authenticatorAttestationResponse[1]);
			if (rootNode == null) {
				return null;
			}
			if(rootNode.has(authenticatorAttestationResponse[0]) && rootNode.has(authenticatorAttestationResponse[2]) && rootNode.has(authenticatorAttestationResponse[4]) && rootNode.has(authenticatorAttestationResponse[5]) && rootNode.has(authenticatorAttestationResponse[6])) {
				JsonNode responseObj = rootNode.findPath(authenticatorAttestationResponse[2]);
				if(responseObj.has(authenticatorAttestationResponse[3])) {
					logger.logToOutput("Found authenticator registration/attestation: ");
					RegistrationResponse rr = om.treeToValue(rootNode, RegistrationResponse.class);
					return rr;
				}
			}
			
		} catch (JsonProcessingException e) {
			logger.logToError(e.getMessage());
		}
		return null;
	}
	
	
	private boolean isPublicKeyCredentialRequestOptions(String response) {
		boolean x = Arrays.stream(publicKeyCredentialRequestOptions).allMatch(response::contains);
		//logger.logToOutput("pub key cred options: " + x);
		return x;
	}
	
	private PublicKeyCredentialRequestOptions findPublicKeyCredentialRequestOptions(String request) {
		ObjectMapper om = new ObjectMapper();
		try {
			JsonNode jt = om.readTree(request);
			JsonNode rootNode = jt.findParent(publicKeyCredentialRequestOptions[2]);
			if (rootNode == null) {
				return null;
			}
			if(rootNode.has(publicKeyCredentialRequestOptions[0]) && rootNode.has(publicKeyCredentialRequestOptions[1])) {
				logger.logToOutput("Found public key request options: ");
				PublicKeyCredentialRequestOptions pkcro = om.treeToValue(rootNode, PublicKeyCredentialRequestOptions.class);
				return pkcro;
			}
			
		} catch (JsonProcessingException e) {
			logger.logToError(e.getMessage());
		}
		return null;
	}
	
	private boolean isAuthenticatorAssertionResponse(String response) {
		boolean x = Arrays.stream(authenticatorAssertionResponse).allMatch(response::contains);
		//logger.logToOutput("attestation response: " + x);
		return x;
	}
	
	private AuthenticationResponse findAuthenticationResponse(String request) {
		ObjectMapper om = new ObjectMapper();
		try {
			JsonNode jt = om.readTree(request);
			JsonNode rootNode = jt.findParent(authenticatorAssertionResponse[1]);
			if (rootNode == null) {
				return null;
			}
			if(rootNode.has(authenticatorAssertionResponse[0]) && rootNode.has(authenticatorAssertionResponse[2]) && rootNode.has(authenticatorAssertionResponse[5]) && rootNode.has(authenticatorAssertionResponse[6]) && rootNode.has(authenticatorAssertionResponse[7])) {
				JsonNode responseObj = rootNode.findPath(authenticatorAssertionResponse[2]);
				if(responseObj.has(authenticatorAssertionResponse[3]) && responseObj.has(authenticatorAssertionResponse[4]))
					logger.logToOutput("Found authenticator authenticate/assertion: ");
					AuthenticationResponse ar = om.treeToValue(rootNode, AuthenticationResponse.class);
					return ar;
			}
			
		} catch (JsonProcessingException e) {
			logger.logToError(e.getMessage());
		}
		return null;
	}
}
