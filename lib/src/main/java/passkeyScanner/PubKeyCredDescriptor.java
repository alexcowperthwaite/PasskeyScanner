package passkeyScanner;

public class PubKeyCredDescriptor {
	private String type;
	private String id;
	private String[] transports;
	
	PubKeyCredDescriptor(){
		super();
	}
	
	PubKeyCredDescriptor(String type, String id, String[] transports){
		this.type = type;
		this.id = id;
		this.setTransports(transports);
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
	public void setAlg(String id) {
		this.id = id;
	}	
	
	@Override
	public String toString() {
		return "\n    {\"type\":\"" + type + "\", \"id\":\"" + id + "\", \"transports\": " + transports.toString() + " }";
		
	}

	public String[] getTransports() {
		return transports;
	}

	public void setTransports(String[] transports) {
		this.transports = transports;
	}


}
