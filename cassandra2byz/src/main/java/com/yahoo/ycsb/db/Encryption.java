package com.yahoo.ycsb.db;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

//Java 8
//import java.util.Base64;
//Java 7
import javax.xml.bind.DatatypeConverter;

public class Encryption {
	//TODO: move to a better place.
	static String publicKeysFolder = [Path_To_Public_Certificates_Folder]
	static String privatePath = [Path_To_Private_JKS_File]
	static public String alias = "clien1";
	static String keystorePass = [KeyStore Password]
	
	final private static String SINGING_ALGO = "SHA256withRSA";
	final private static String SYM_SINGING_ALGO = "HmacSHA256";

	PrivateKey prv = null;
	PublicKey pub = null;
	Map<String, PublicKey> publicKeys = null;
	Map<String, Key> symmetricKeys = null;
	
	// Singelton
    private static Encryption instance = null;

    private Encryption(){}

    public static Encryption getInstance(){
    	if (instance == null) {
    		instance = new Encryption();
    		try {
				instance.init(privatePath, alias, keystorePass);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
    	}
    	
        return instance;
    }
   
    public static void initS(String privatePath, String alias, String keystorePass) throws Exception {
    	instance.init(privatePath, alias, keystorePass);
    }
    
    public void init(String privatePath, String alias, String keystorePass) throws Exception {
		prv = Encryption.loadPrivateKey(privatePath, alias, keystorePass);
		if (prv == null) {
			System.err.println("Failed obtaining keystore");
		}
		publicKeys = getAllPublicKeys();
		symmetricKeys = getAllSymmetricKeys();
		
		if (publicKeys == null) {
			System.err.println("Failed obtaining certificates");
		}
		if (symmetricKeys == null) {
			System.err.println("Failed obtaining symmetric keys");
		}
		
		if (prv == null) {
			System.err.println("Failed obtaining keystore");
		}
		
		System.out.println("Loaded certificates: " + publicKeys.size());
		
    }
    
    private static Map<String,PublicKey> getAllPublicKeys(){
    	Map<String,PublicKey> mapping = new HashMap<String,PublicKey>();
    	Path dir = FileSystems.getDefault().getPath(publicKeysFolder);
    	try (DirectoryStream<Path> stream = Files.newDirectoryStream(dir, "*.cer")) {
    	    for (Path entry: stream) {
    	    	String certPath = entry.toString();
    	        String name = entry.getFileName().toString().split(".cer")[0];
    	        PublicKey pk = null;
    	        try {
					pk = loadPublicKey(certPath);
				} catch (Exception e) {
					System.err.println("Failed loading cert: " + certPath);
					continue;
				}
    	        
    	        if (pk == null){
    	        	System.err.println("Failed loading cert (null): " + certPath);
					continue;
    	        }
    	        
    	        mapping.put(name, pk);
    	    }
    	} catch (IOException x) {
    	    // IOException can never be thrown by the iteration.
    	    // In this snippet, it can // only be thrown by newDirectoryStream.
    	    System.err.println(x);
    	}
    	
    	return mapping;
    }
    
    private static Map<String,Key> getAllSymmetricKeys(){
    	Map<String,Key> mapping = new HashMap<String,Key>();

	    for (Map.Entry<String, String> entry: SymetricKeys.keysMapping.entrySet()) {
	        String name = entry.getKey();
	        Key key = null;
	        try {
	        	key = loadSymmetricKey(entry.getValue());
			} catch (Exception e) {
				System.err.println("Failed loading key: " + name);
				continue;
			}
	        
	        if (key == null){
	        	System.err.println("Failed loading key (null): " + name);
				continue;
	        }
	        
	        mapping.put(name, key);
	    }
    	
    	return mapping;
    }
    
	public static Key loadSymmetricKey(String key) throws Exception{
		Key signingKey = new SecretKeySpec(key.getBytes(), SYM_SINGING_ALGO);
		return signingKey;
	}
    
	public static PrivateKey loadPrivateKey(String path, String alias, String keystorePass) throws Exception{
		KeyStore ks = KeyStore.getInstance("JKS");
		FileInputStream ksfis = new FileInputStream(path); 
		BufferedInputStream ksbufin = new BufferedInputStream(ksfis);
	
		ks.load(ksbufin, keystorePass.toCharArray());
		PrivateKey priv = (PrivateKey) ks.getKey(alias, keystorePass.toCharArray());
		
		return priv;
	}
	
	public static PublicKey loadPublicKey(String path) throws Exception{
		FileInputStream certfis = new FileInputStream(path);
		java.security.cert.CertificateFactory cf =
		    java.security.cert.CertificateFactory.getInstance("X.509");
		java.security.cert.Certificate cert =  cf.generateCertificate(certfis);
		PublicKey pub = cert.getPublicKey();
		
		return pub;
	}
		
	public byte[] signData(byte[] data) throws Exception 
	{
		Signature signature = Signature.getInstance(SINGING_ALGO);
		
		signature.initSign(prv);
		signature.update(data);
		// Java 8
		//return Base64.getEncoder().encode(signature.sign());
		// Java 7
		return DatatypeConverter.printBase64Binary(signature.sign()).getBytes();
	}

	public boolean verifyData(String signer, byte[] data, byte[] sigBytes) throws 
		NoSuchAlgorithmException, 
		InvalidKeyException, 
		SignatureException, 
		InvalidKeySpecException 
	{
		if (!publicKeys.containsKey(signer)){
			System.err.println("No such signer exists in the system:" + signer);
			return false;
		}
		
		Signature signature = Signature.getInstance(SINGING_ALGO);
		
		signature.initVerify(publicKeys.get(signer));
		signature.update(data);
		// Java 8
		// return signature.verify(Base64.getDecoder().decode(sigBytes));
		// Java 7
		byte[] decoded = DatatypeConverter.parseBase64Binary(new String(sigBytes));
		return signature.verify(decoded);
	}
	
	private String buildClientNodeString(String client, String node) {
		return client + "-" + node;
	}
	
	public byte[] signDataSym(byte[] data, String client, String node) throws Exception {
		Key key = symmetricKeys.get(buildClientNodeString(client,node));
		if (key == null){
			return null;
		}
		Mac mac = Mac.getInstance(SYM_SINGING_ALGO);
		mac.init(key);
		byte[] sign = mac.doFinal(data);
		return DatatypeConverter.printBase64Binary(sign).getBytes();
	}
	
	public boolean verifySymData(byte[] data, byte[] sigBytes, String client, String node) throws Exception	{
		byte[] localSigned = signDataSym(data, client, node);
		return Arrays.equals(localSigned, sigBytes);
	}
}