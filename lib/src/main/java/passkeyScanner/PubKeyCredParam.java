package passkeyScanner;

public class PubKeyCredParam {
	private String type;
	private long alg;
	
	PubKeyCredParam(){
		super();
	}
	
	PubKeyCredParam(String type, int alg){
		this.type = type;
		this.alg = alg;
	}
	
	public String getType() {
		return type;
	}
	public void setType(String type) {
		this.type = type;
	}
	public long getAlg() {
		return alg;
	}
	public void setAlg(long alg) {
		this.alg = alg;
	}	
	
	@Override
	public String toString() {
		return "\n    {\"type\":\"" + type + "\", \"alg\":" + Long.toString(alg) + " }";
		
	}
}
