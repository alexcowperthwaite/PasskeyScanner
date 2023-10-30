package passkeyScanner;

import java.util.HashMap;
import java.util.HashSet;
import java.lang.Long;

import burp.api.montoya.logging.Logging;

public class IANACoseAlgorithms {

	private HashMap<Long, IANACoseAlgorithm> algs;
	private static IANACoseAlgorithms instance;
	private Logging logger; 

	private String[][] algorithms = {
			{"RS1","-65535","RSASSA-PKCS1-v1_5 using SHA-1","Deprecated","asymmetric"},
			{"A128CTR","-65534","AES-CTR w/ 128-bit key","Deprecated","symmetric"},
			{"A192CTR","-65533","AES-CTR w/ 192-bit key","Deprecated","symmetric"},
			{"A256CTR","-65532","AES-CTR w/ 256-bit key","Deprecated","symmetric"},
			{"A128CBC","-65531","AES-CBC w/ 128-bit key","Deprecated","symmetric"},
			{"A192CBC","-65530","AES-CBC w/ 192-bit key","Deprecated","symmetric"},
			{"A256CBC","-65529","AES-CBC w/ 256-bit key","Deprecated","symmetric"},
			{"WalnutDSA","-260","WalnutDSA signature","No","asymmetric"},
			{"RS512","-259","RSASSA-PKCS1-v1_5 using SHA-512","No","asymmetric"},
			{"RS384","-258","RSASSA-PKCS1-v1_5 using SHA-384","No","asymmetric"},
			{"RS256","-257","RSASSA-PKCS1-v1_5 using SHA-256","No","asymmetric"},
			{"ES256K","-47","ECDSA using secp256k1 curve and SHA-256","No","asymmetric"},
			{"HSS-LMS","-46","HSS/LMS hash-based digital signature","Yes","asymmetric"},
			{"SHAKE256","-45","SHAKE-256 512-bit Hash Value","Yes","hash"},
			{"SHA-512","-44","SHA-2 512-bit Hash","Yes","hash"},
			{"SHA-384","-43","SHA-2 384-bit Hash","Yes","hash"},
			{"RSAES-OAEP w/ SHA-512","-42","RSAES-OAEP w/ SHA-512","Yes","asymmetric"},
			{"RSAES-OAEP w/ SHA-256","-41","RSAES-OAEP w/ SHA-256","Yes","asymmetric"},
			{"RSAES-OAEP w/ RFC 8017 default parameters","-40","RSAES-OAEP w/ SHA-1","Yes","asymmetric"},
			{"PS512","-39","RSASSA-PSS w/ SHA-512","Yes","asymmetric"},
			{"PS384","-38","RSASSA-PSS w/ SHA-384","Yes","asymmetric"},
			{"PS256","-37","RSASSA-PSS w/ SHA-256","Yes","asymmetric"},
			{"ES512","-36","ECDSA w/ SHA-512","Yes","asymmetric"},
			{"ES384","-35","ECDSA w/ SHA-384","Yes","asymmetric"},
			{"ECDH-SS + A256KW","-34","ECDH SS w/ Concat KDF and AES Key Wrap w/ 256-bit key","Yes","asymmetric"},
			{"ECDH-SS + A192KW","-33","ECDH SS w/ Concat KDF and AES Key Wrap w/ 192-bit key","Yes","asymmetric"},
			{"ECDH-SS + A128KW","-32","ECDH SS w/ Concat KDF and AES Key Wrap w/ 128-bit key","Yes","asymmetric"},
			{"ECDH-ES + A256KW","-31","ECDH ES w/ Concat KDF and AES Key Wrap w/ 256-bit key","Yes","asymmetric"},
			{"ECDH-ES + A192KW","-30","ECDH ES w/ Concat KDF and AES Key Wrap w/ 192-bit key","Yes","asymmetric"},
			{"ECDH-ES + A128KW","-29","ECDH ES w/ Concat KDF and AES Key Wrap w/ 128-bit key","Yes","asymmetric"},
			{"ECDH-SS + HKDF-512","-28","ECDH SS w/ HKDF - generate key directly","Yes","asymmetric"},
			{"ECDH-SS + HKDF-256","-27","ECDH SS w/ HKDF - generate key directly","Yes","asymmetric"},
			{"ECDH-ES + HKDF-512","-26","ECDH ES w/ HKDF - generate key directly","Yes","asymmetric"},
			{"ECDH-ES + HKDF-256","-25","ECDH ES w/ HKDF - generate key directly","Yes","asymmetric"},
			{"SHAKE128","-18","SHAKE-128 256-bit Hash Value","Yes","hash"},
			{"SHA-512/256","-17","SHA-2 512-bit Hash truncated to 256-bits","Yes","hash"},
			{"SHA-256","-16","SHA-2 256-bit Hash","Yes","hash"},
			{"SHA-256/64","-15","SHA-2 256-bit Hash truncated to 64-bits","Filter Only","hash"},
			{"SHA-1","-14","SHA-1 Hash","Filter Only","hash"},
			{"direct+HKDF-AES-256","-13","Shared secret w/ AES-MAC 256-bit key","Yes","symmetric"},
			{"direct+HKDF-AES-128","-12","Shared secret w/ AES-MAC 128-bit key","Yes","symmetric"},
			{"direct+HKDF-SHA-512","-11","Shared secret w/ HKDF and SHA-512","Yes","symmetric"},
			{"direct+HKDF-SHA-256","-10","Shared secret w/ HKDF and SHA-256","Yes","symmetric"},
			{"EdDSA","-8","EdDSA","Yes","asymmetric"},
			{"ES256","-7","ECDSA w/ SHA-256","Yes","asymmetric"},
			{"direct","-6","Direct use of CEK","Yes","symmetric"},
			{"A256KW","-5","AES Key Wrap w/ 256-bit key","Yes","symmetric"},
			{"A192KW","-4","AES Key Wrap w/ 192-bit key","Yes","symmetric"},
			{"A128KW","-3","AES Key Wrap w/ 128-bit key","Yes","symmetric"},
			{"Reserved","0","","No","None"},
			{"A128GCM","1","AES-GCM mode w/ 128-bit key 128-bit tag","Yes","symmetric"},
			{"A192GCM","2","AES-GCM mode w/ 192-bit key 128-bit tag","Yes","symmetric"},
			{"A256GCM","3","AES-GCM mode w/ 256-bit key 128-bit tag","Yes","symmetric"},
			{"HMAC 256/64","4","HMAC w/ SHA-256 truncated to 64 bits","Yes","symmetric"},
			{"HMAC 256/256","5","HMAC w/ SHA-256","Yes","symmetric"},
			{"HMAC 384/384","6","HMAC w/ SHA-384","Yes","symmetric"},
			{"HMAC 512/512","7","HMAC w/ SHA-512","Yes","symmetric"},
			{"AES-CCM-16-64-128","10","AES-CCM mode 128-bit key 64-bit tag 13-byte nonce","Yes","symmetric"},
			{"AES-CCM-16-64-256","11","AES-CCM mode 256-bit key 64-bit tag 13-byte nonce","Yes","symmetric"},
			{"AES-CCM-64-64-128","12","AES-CCM mode 128-bit key 64-bit tag 7-byte nonce","Yes","symmetric"},
			{"AES-CCM-64-64-256","13","AES-CCM mode 256-bit key 64-bit tag 7-byte nonce","Yes","symmetric"},
			{"AES-MAC 128/64","14","AES-MAC 128-bit key 64-bit tag","Yes","symmetric"},
			{"AES-MAC 256/64","15","AES-MAC 256-bit key 64-bit tag","Yes","symmetric"},
			{"ChaCha20/Poly1305","24","ChaCha20/Poly1305 w/ 256-bit key 128-bit tag","Yes","symmetric"},
			{"AES-MAC 128/128","25","AES-MAC 128-bit key 128-bit tag","Yes","symmetric"},
			{"AES-MAC 256/128","26","AES-MAC 256-bit key 128-bit tag","Yes","symmetric"},
			{"AES-CCM-16-128-128","30","AES-CCM mode 128-bit key 128-bit tag 13-byte nonce","Yes","symmetric"},
			{"AES-CCM-16-128-256","31","AES-CCM mode 256-bit key 128-bit tag 13-byte nonce","Yes","symmetric"},
			{"AES-CCM-64-128-128","32","AES-CCM mode 128-bit key 128-bit tag 7-byte nonce","Yes","symmetric"},
			{"AES-CCM-64-128-256","33","AES-CCM mode 256-bit key 128-bit tag 7-byte nonce","Yes","symmetric"},
			{"IV-GENERATION","34","For doing IV generation for symmetric algorithms.","No","symmetric"}
		};
	
	private IANACoseAlgorithms(Logging logger) {
		this.logger = logger;
		this.algs = new HashMap<Long, IANACoseAlgorithm>();
		initAlgsFromArray();
	}
	
	private void initAlgsFromArray() {
		for(int i =0; i < algorithms.length; i++) {
			this.algs.put(Long.decode(algorithms[i][1]), new IANACoseAlgorithm(algorithms[i][0], Long.decode(algorithms[i][1]), algorithms[i][2], algorithms[i][3], algorithms[i][4]));
		}
	}
	
	public static IANACoseAlgorithms getInstance(Logging logger) {
		if (instance == null) {
			instance = new IANACoseAlgorithms(logger);
		}
		
		return instance;
	}
	
	public void enableLogging(Logging logger) {
		this.logger = logger;
		
	}
	
	public boolean usingNotRecommendedAlg(Long alg) {
		IANACoseAlgorithm a = this.algs.get(alg);
		return (!a.getRecommended().equals("Yes")) || (!a.getType().equals("asymmetric"));
	}
	
	public HashSet<IANACoseAlgorithm> usingNotRecommendedAlg(PubKeyCredParam[] params) {
		HashSet<IANACoseAlgorithm> badAlgs = new HashSet<IANACoseAlgorithm>();
		
		for (int i=0; i<params.length; i++) {
			if (usingNotRecommendedAlg(Long.valueOf(params[i].getAlg()))) {
				badAlgs.add(algs.get(Long.valueOf(params[i].getAlg())));
			}
		}
		
		return badAlgs;
	}
		
	
	public class IANACoseAlgorithm {
		private String name;
		private Long value;
		private String description;
		private String recommended;
		private String type;
		
		public IANACoseAlgorithm(String name, Long value, String description, String recommended, String type) {
			this.name = name;
			this.value = value;
			this.description = description;
			this.recommended = recommended;
			this.type = type;
		}
		
		public String getName() {
			return name;
		}

		public void setName(String name) {
			this.name = name;
		}

		public Long getValue() {
			return value;
		}

		public void setValue(Long value) {
			this.value = value;
		}

		public String getDescription() {
			return description;
		}

		public void setDescription(String description) {
			this.description = description;
		}

		public String getRecommended() {
			return recommended;
		}

		public void setRecommended(String recommended) {
			this.recommended = recommended;
		}

		public String getType() {
			return type;
		}

		public void setType(String type) {
			this.type = type;
		}
	}
}
