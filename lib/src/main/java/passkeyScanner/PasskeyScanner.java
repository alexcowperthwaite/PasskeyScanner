package passkeyScanner;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;

public class PasskeyScanner implements BurpExtension {

	@Override
	public void initialize(MontoyaApi api) {
		
		Logging logging = api.logging();
		
        api.extension().setName("Passkey Scanner");
        api.scanner().registerScanCheck(new WebAuthNScanner(api, logging));

	}

}
