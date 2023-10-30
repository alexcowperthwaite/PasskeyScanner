package passkeyScanner;

public class AuthenticatorSelection {
	private boolean requireResidentKey;
	private String residentKey;
	private String userVerification;
	
	AuthenticatorSelection(){
		super();
	}
	
	AuthenticatorSelection(boolean requiresResidentKey, String residentKey, String userVerification){
		this.requireResidentKey = requiresResidentKey;
		this.residentKey = residentKey;
		this.userVerification = userVerification;
	}
	
	public boolean isRequireResidentKey() {
		return requireResidentKey;
	}
	public void setRequireResidentKey(boolean requireResidentKey) {
		this.requireResidentKey = requireResidentKey;
	}
	public String getResidentKey() {
		return residentKey;
	}
	public void setResidentKey(String residentKey) {
		this.residentKey = residentKey;
	}
	public String getUserVerification() {
		return userVerification;
	}
	public void setUserVerification(String userVerification) {
		this.userVerification = userVerification;
	}

	@Override
	public String toString() {
		return "{\n    \"requiresResidentKey\":\"" + requireResidentKey + "\",\n    \"residentKey\":\"" + residentKey + "\",\n    \"userVerification\":\"" + userVerification + "\"\n  }";
	}
}
