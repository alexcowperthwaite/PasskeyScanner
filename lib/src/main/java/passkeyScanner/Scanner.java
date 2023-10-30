package passkeyScanner;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.data.attestation.authenticator.Curve;
import com.webauthn4j.data.attestation.authenticator.EC2COSEKey;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import passkeyScanner.IANACoseAlgorithms.IANACoseAlgorithm;




public class Scanner {
	private IANACoseAlgorithms algs;
	private Logging logger;
	private List<AuditIssue> findings;
	
	public Scanner(Logging logger) {
		this.logger = logger;	
		logger.logToOutput("Initialize Scanner");
		this.findings = new ArrayList<AuditIssue>();
		algs = IANACoseAlgorithms.getInstance(logger);
	}
	
	
	public AuditResult getFindings() {
		return AuditResult.auditResult(findings);
	}
	
	public void scanPubKeyCredCreationOptions(HttpRequestResponse baseRequestResponse, PublicKeyCredentialCreationOptions pkcco) {
		
		List<AuditIssue> auditIssueList = checkRecommendedPubKeyAlgs(baseRequestResponse, pkcco);
		//logger.logToOutput("Found " + auditIssueList.size() + " pub key cred option issues");		
		findings.addAll(auditIssueList);		
		
		List<AuditIssue> auditIssueList2 = checkUserVerificationRequired(baseRequestResponse, pkcco);
		//logger.logToOutput("Found " + auditIssueList2.size() + " pub key cred option issues");
		findings.addAll(auditIssueList2);
		
		List<AuditIssue> auditIssueList3 = checkChallengeLength(baseRequestResponse, pkcco);
		//logger.logToOutput("Found " + auditIssueList3.size() + " pub key cred option issues");
		findings.addAll(auditIssueList3);
		
		List<AuditIssue> auditIssueList4 = checkUserHandlePII(baseRequestResponse, pkcco);
		//logger.logToOutput("Found " + auditIssueList4.size() + " pub key cred option issues");
		findings.addAll(auditIssueList4);
	}
	
	public void scanPubKeyCredRequestOptions(HttpRequestResponse baseRequestResponse, PublicKeyCredentialRequestOptions pkcro) {
		List<AuditIssue> auditIssueList = checkChallengeLength(baseRequestResponse, pkcro);
		//logger.logToOutput("Found " + auditIssueList.size() + " pub key cred option issues");
		findings.addAll(auditIssueList);
		
		List<AuditIssue> auditIssueList2 = checkAllowCredentialsDisclosure(baseRequestResponse, pkcro);
		//logger.logToOutput("Found " + auditIssueList2.size() + " pub key cred option issues");
		findings.addAll(auditIssueList2);
	}
	
	public void scanRegistrationResponse(HttpRequestResponse baseRequestResponse, RegistrationResponse rr) {
		List<AuditIssue> auditIssueList = checkECPublicKeyPoints(baseRequestResponse, rr);
		//logger.logToOutput("Found " + auditIssueList.size() + " registration response issues");
		findings.addAll(auditIssueList);	
	}
	
	public void scanAuthenticationResponse(HttpRequestResponse baseRequestResponse, AuthenticationResponse rr) {
		//logger.logToOutput("Found " + auditIssueList.size() + " issues");
		//findings.addAll(auditIssueList);	
	}
	
	
	
	/**
	 * 
	 * @param pkcco PublicKeyCredentialCreationOptions object
	 * @return List<AuditIssue> the algorithms that are "not recommended"
	 * 
	 * Verify the PublicKeyCredParams (algorithm) that are offered during creation.
	 * https://www.iana.org/assignments/cose/cose.xhtml#algorithms algorithm codes and "recommended" for use.
	 */
	
	private List<AuditIssue> checkRecommendedPubKeyAlgs(HttpRequestResponse baseRequestResponse, PublicKeyCredentialCreationOptions pkcco){
		
		final String title = "Passkey Creation with Not Recommended Algorithm";
		final String description = "The web server has provided a list of acceptable key formats to create a Passkey public key credential. This list includes public key formats that are not acceptable for Passkeys. "
				+ "This criteria means that either the algoirthm is not recommend in the CBOR Object Signing and Encryption (COSE) algorithm registry, or it is a symmetic key algorithm. The unacceptable algorithm is \"";
		final String description2 = "\" which has a corresponding algorithm identifier of ";
		final String remediation = "The relaying party should update the list of supported algoithms exclude algorithms that are not recommended by COSE and ensure that only asymmetric algorithms are included.";
		final String baseUrl = baseRequestResponse.url();
        final String background = "When creating a Passkey, the relaying party (web server) and authenticator need to agree on an acceptable algorithm. This process starts with the relaying party responding with"
        		+ " a Public Key Credential Creation Options response. This structure includes an order list of acceptable algorithms in the \'pubKeyCredParams\' variable. Each option in the list has an algorithm"
        		+ " identifier which is defined in COSE Algorithm Registry (https://www.iana.org/assignments/cose/cose.xhtml#algorithms). The registry includes a recommendation for algorithms which should no longer"
        		+ " be used. Symmetric key algorithms are also included in this registry but are not acceptable for public key authenticaiton. The reason an algorithm is not recommended depends on the specific algorithm. "
        		+ "RSA PKCSv.1 is a commonly used algorithm that is not recommended, it was \"Not recommended for new application\" by RFC 3447 in 2003 (https://www.rfc-editor.org/rfc/rfc3447.html#section-8.2). See "
        		+ "also RFC 7518 (https://www.rfc-editor.org/rfc/rfc7518.html#section-8.3) and RFC 8812 (https://www.rfc-editor.org/rfc/rfc8812.html#RSASSA-PKCS1-v1_5_SHA-2_considerations)";
        final String remediationBackground = "";
		
		HashSet<IANACoseAlgorithm> res = algs.usingNotRecommendedAlg(pkcco.getPubKeyCredParams());
		List<AuditIssue> r	= new ArrayList<AuditIssue>();
		for (IANACoseAlgorithm a : res) {
				r.add(AuditIssue.auditIssue(title, description + a.getName() + description2 + a.getValue(), remediation, baseUrl, AuditIssueSeverity.LOW, AuditIssueConfidence.CERTAIN, background, remediationBackground, AuditIssueSeverity.LOW, baseRequestResponse ));
				logger.logToOutput("Finding: Bad public key algorithm: " + a.getName());
		}
		return r;		
	}
	
	/**
	 * 
	 * @param pkcco PublicKeyCredentialCreationOptions object
	 * @param baseRequestResponse the HTTP request/response object
	 * @return List<AuditIssue> the algorithms that are "not recommended"
	 * 
	 * Check if the authenticator requires user verification -  options required/preferred/discouraged
	 *
	 */
	
	private List<AuditIssue> checkUserVerificationRequired(HttpRequestResponse baseRequestResponse, PublicKeyCredentialCreationOptions pkcco){
		
		final String title = "Passkey Authenticator Does Not Require User Verfication";
		final String description = "The authenicator being created does not require user verification. The authenticator being created does not require user verification which weakens the authentication process, especially "
				+ "in the case the device is lost or stolen. The user verification parameter is " + pkcco.getAuthenticatorSelection().getUserVerification();
		final String remediation = "The web server (relaying party) should set the user verification option to \"required\" in most cases. If a user is expected to be authenticating frequently and the application owner has "
				+ "some risk tolerance, then a setting of \"preferred\" can be used";
		final String baseUrl = baseRequestResponse.url();
        final String background = "When creating an authenicator, the relaying party can specify the level of user verification. Three options are available \"required\", \"preferred\" or \"optional\". User verification will"
        		+ " depend on the device capability and configuration but is typically a biometric such as fingerprint or faceprint, or the login password. User verification \"perferred\" option may be used, which does not "
        		+ "necessitate verification each time which helps the user experience is frequent authentication is expected. When user verification is \"preferred\" the system will decide if user verification is required "
        		+ "which, for example, may not require verification if it has been performed recently.";
        final String remediationBackground = "User verification \"required\" enforces the strongest security, but \"preferred\" may be appropriate for some applications.";
		
        
        List<AuditIssue> r	= new ArrayList<AuditIssue>();
		if (!pkcco.getAuthenticatorSelection().getUserVerification().equals("required")) {
			r.add(AuditIssue.auditIssue(title, description, remediation, baseUrl, AuditIssueSeverity.LOW, AuditIssueConfidence.CERTAIN, background, remediationBackground, AuditIssueSeverity.LOW, baseRequestResponse ));
			logger.logToOutput("Finding: User verficiation not \"required\"");
		}
		return r;		
	}
	
	/**
	 * 
	 * @param pkcco PublicKeyCredentialCreationOptions object
	 * @param baseRequestResponse the HTTP request/response object
	 * @return List<AuditIssue> challenges that are less than 16 bytes
	 * 
	 * Check if the PK creation challenge string is of sufficient length/entropy (at least 16 bytes)
	 *
	 */
	
	private List<AuditIssue> checkChallengeLength(HttpRequestResponse baseRequestResponse, PublicKeyCredentialCreationOptions pkcco){
		
		final String title = "Passkey Weak Authentication Challenge";
		final String description = "The challenge issued by the web server (relaying party) is not of sufficient length. This makes the challenge potentially weak or guessable which breaks the cryptographic guarentees "
				+ "of the the authentication ceremony and could allow an attacker predict a challenge which is useful in a replay attack" ;
		final String remediation = "The relaying party should issue challenges of at least 16 bytes (128 bits) and 32 bytes (256 bits) is preferred";
		final String baseUrl = baseRequestResponse.url();
        final String background = "The relaying party issues a random challenge string which the authenicator must cryptographically sign to complete the authentication process. https://w3c.github.io/webauthn/#sctn-cryptographic-challenges";
        final String remediationBackground = "";
		
        
        List<AuditIssue> r	= new ArrayList<AuditIssue>();
		if (pkcco.getDecodedChallenge().length < 16) {
			r.add(AuditIssue.auditIssue(title, description, remediation, baseUrl, AuditIssueSeverity.LOW, AuditIssueConfidence.CERTAIN, background, remediationBackground, AuditIssueSeverity.LOW, baseRequestResponse ));
			logger.logToOutput("Found Insufficient Entropy of Authetnication Challenge");
		}
		return r;		
	}
	
	/**
	 * 
	 * @param pkcco PublicKeyCredentialRequestOptions object
	 * @param baseRequestResponse the HTTP request/response object
	 * @return List<AuditIssue> challenges that are less than 16 bytes
	 * 
	 * Check if the PK credential challenge string is of sufficient length/entropy (at least 16 bytes)
	 *
	 */
	
	private List<AuditIssue> checkChallengeLength(HttpRequestResponse baseRequestResponse, PublicKeyCredentialRequestOptions pkcro){
		
		final String title = "Passkey Weak Authentication Challenge";
		final String description = "The challenge issued by the web server (relaying party) is not of sufficient length. This makes the challenge potentially weak or guessable which breaks the cryptographic guarentees "
				+ "of the the authentication ceremony and could allow an attacker predict a challenge which is useful in a replay attack" ;
		final String remediation = "The relaying party should issue challenges of at least 16 bytes (128 bits) and 32 bytes (256 bits) is preferred";
		final String baseUrl = baseRequestResponse.url();
        final String background = "The relaying party issues a random challenge string which the authenicator must cryptographically sign to complete the authentication process. https://w3c.github.io/webauthn/#sctn-cryptographic-challenges";
        final String remediationBackground = "";
		
        
        List<AuditIssue> r	= new ArrayList<AuditIssue>();
        
		if (pkcro.getDecodedChallenge().length < 16) {
			r.add(AuditIssue.auditIssue(title, description, remediation, baseUrl, AuditIssueSeverity.LOW, AuditIssueConfidence.CERTAIN, background, remediationBackground, AuditIssueSeverity.LOW, baseRequestResponse ));
			logger.logToOutput("Found Insufficient Entropy of Authetnication Challenge");
		}
		return r;		
	}
	
	/**
	 * 
	 * @param pkcco PublicKeyCredentialRequestOptions object
	 * @param baseRequestResponse the HTTP request/response object
	 * @return List<AuditIssue> if the allowCredentials discloses non-public key types
	 * 
	 * Check if the allowCredentials parameter is present, if so, inspect the PublicKeyCredentialDescriptors for any type != "public-key"
	 *
	 */
	
	private List<AuditIssue> checkAllowCredentialsDisclosure(HttpRequestResponse baseRequestResponse, PublicKeyCredentialRequestOptions pkcro){
		
		final String title = "Passkeys AllowCredentials Discloses Accounts with Weak Credentials";
		final String description = "The allowCredentials parameter specifies credentials that a relaying party will accept to authenticate a user. This parameter can also disclose if user accounts have a non-webauthn "
				+ "credential allowed. This information can disclose if a weaker form of authentication such as passwords are permitted, which an attacker could target in subsequent attacks." ;
		final String remediation = "The allowCredentials parameter should only be used for webauthn credentials, and not disclose accounts with passwords or other weaker forms of authentication. The absense of a webauthn"
				+ "credential could also disclose that a weaker form of authentication is in use.";
		final String baseUrl = baseRequestResponse.url();
        final String background = "The relaying party submits the allowedCredentials request to a client (browser) in the Public Key Credential Request Options structure. The client uses this information to discover "
        		+ "if the available authenticators have a matching credential. This parameter can also disclose if user accounts have a non-webauthn credential allowed.\n "
        		+ "https://w3c.github.io/webauthn/#sctn-unprotected-account-detection";
        final String remediationBackground = "";
		
        
        List<AuditIssue> r	= new ArrayList<AuditIssue>();
		if (pkcro.getAllowCredentials() != null && pkcro.getAllowCredentials().length > 0) {
			PublicKeyCredentialDescriptor[] ac = pkcro.getAllowCredentials();
			for (PublicKeyCredentialDescriptor pkcd : ac) {
				if (!pkcd.getType().equals("public-key")) {
					r.add(AuditIssue.auditIssue(title, description, remediation, baseUrl, AuditIssueSeverity.LOW, AuditIssueConfidence.CERTAIN, background, remediationBackground, AuditIssueSeverity.LOW, baseRequestResponse ));
					logger.logToOutput("Found AllowCredentials Info Disclosure");
				}
			}
		}
		return r;		
	}

	
	/**
	 * 
	 * @param pkcco PublicKeyCredentialRequestOptions object
	 * @param baseRequestResponse the HTTP request/response object
	 * @return List<AuditIssue> if the user.id contains PII
	 * 
	 * Check if the public key credential creation options object user.id field contains PII, in this check we only look for email formats, but usernames should be manually checked as well. 
	 *
	 */
	
	private List<AuditIssue> checkUserHandlePII(HttpRequestResponse baseRequestResponse, PublicKeyCredentialCreationOptions pkcco){
		
		final String title = "Passkeys User Handle Contains Personally Identifyable Information (PII)";
		final String description = "The Public Key Creation Options object, specifies a user.id field that contains personally identifyable information, an email in this case. The user.id "
				+ "field will be stored by the authenticator and could allow malicious relaying parties (websites) to discover information regarding the user of this account. The user.id "
				+ "field should be a randomly generated identifier, that an attacker cannot use to assocaite with any external user identifier" ;
		final String remediation = "The user.id field should be a unique randomized identifier.";
		final String baseUrl = baseRequestResponse.url();
        final String background = "14.6 Privacy Considerations for Relaying Parties - User Handle Contents https://w3c.github.io/webauthn/#sctn-privacy-considerations-rp";
        final String remediationBackground = "";
        
        final String EMAIL_VALID_REGEX = "[_A-Za-z0-9+-]+(?:[.'’][_A-Za-z0-9-]+)*@[_A-Za-z0-9-]+(?:\\.[_A-Za-z0-9-]+)*\\.[A-Za-z]{2,}$";
		
        
        List<AuditIssue> r	= new ArrayList<AuditIssue>();
		Map<String, String> user = pkcco.getUser();
		String handle = user.get("id");
		if (handle != null) {
			if (handle.matches(EMAIL_VALID_REGEX)) {
				r.add(AuditIssue.auditIssue(title, description, remediation, baseUrl, AuditIssueSeverity.LOW, AuditIssueConfidence.CERTAIN, background, remediationBackground, AuditIssueSeverity.LOW, baseRequestResponse ));
				logger.logToOutput("Found Email (PII) in User.id");
			
			}
		}
		return r;		
	}
	
	
	/**
	 * 
	 * @param rr RegistrationResponse object
	 * @param baseRequestResponse the HTTP request/response object
	 * @return List<AuditIssue> checks COSE Public key forma
	 * 
	 * Check if the created public key follows the required key and curve point formats described in https://w3c.github.io/webauthn/#sctn-alg-identifier. 
	 *
	 */
	
	private List<AuditIssue> checkECPublicKeyPoints(HttpRequestResponse baseRequestResponse, RegistrationResponse rr){
		
		final String title = "Passkey Public Key Credential Does Not Conform with Standards";
		String description = "" ;
		final String remediation = "Ensure that the authenticator is generating valid public keys and using the acceptable algorithms.";
		final String baseUrl = baseRequestResponse.url();
        final String background = "The public key that is returned to the server does not conform with the WebAuthN Standards. See https://w3c.github.io/webauthn/#sctn-alg-identifier";
        final String remediationBackground = "";		
        
        List<AuditIssue> r	= new ArrayList<AuditIssue>();
		AttestationObject aar = rr.getResponse().decodeAttestationObject();
		COSEKey key = aar.getAuthenticatorData().getAttestedCredentialData().getCOSEKey();
		if(key instanceof EC2COSEKey) {
			EC2COSEKey ec = (EC2COSEKey)key;
			if (ec.getAlgorithm() == COSEAlgorithmIdentifier.ES256) {
				if(ec.getCurve() != Curve.SECP256R1) {
					description = "The algorithm ES256 with the COSE identifier of -7, does not specific the correct curve P-256/SECP256R1 with COSE identifier (1). This could lead to cryptographic attacks on the generated keypair.";
					r.add(AuditIssue.auditIssue(title, description, remediation, baseUrl, AuditIssueSeverity.LOW, AuditIssueConfidence.CERTAIN, background, remediationBackground, AuditIssueSeverity.LOW, baseRequestResponse ));
					logger.logToOutput("Algorithm and Curve mismatch ES256 <> SECP256R1");
					//EC2COSEKey stores key in x, y point formats, which are forced to be uncompressed
				}
			}
			if (ec.getAlgorithm() == COSEAlgorithmIdentifier.ES384) {
				if(ec.getCurve() != Curve.SECP384R1) {
					description = "The algorithm ES384 with the COSE identifier of -35, does not specific the correct curve P-384/SECP384R1 with COSE identifier (2). This could lead to cryptographic attacks on the generated keypair.";
					r.add(AuditIssue.auditIssue(title, description, remediation, baseUrl, AuditIssueSeverity.LOW, AuditIssueConfidence.CERTAIN, background, remediationBackground, AuditIssueSeverity.LOW, baseRequestResponse ));
					logger.logToOutput("Algorithm and Curve mismatch ES384 <> SECP384R1");
				}
			}
			if (ec.getAlgorithm() == COSEAlgorithmIdentifier.ES512) {
				if(ec.getCurve() != Curve.SECP521R1) {
					description = "The algorithm ES512 with the COSE identifier of -36, does not specific the correct curve P-521/SECP521R1 with COSE identifier (3). This could lead to cryptographic attacks on the generated keypair.";
					r.add(AuditIssue.auditIssue(title, description, remediation, baseUrl, AuditIssueSeverity.LOW, AuditIssueConfidence.CERTAIN, background, remediationBackground, AuditIssueSeverity.LOW, baseRequestResponse ));
					logger.logToOutput("Algorithm and Curve mismatch ES512 <> SECP521R1");
				}
			}
				
		}
			
		return r;		
	}
}
