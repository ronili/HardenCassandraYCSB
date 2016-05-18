package com.yahoo.ycsb.db;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.AbstractMap;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Random;
import java.util.Set;

import com.datastax.driver.core.Cluster;
import com.datastax.driver.core.ResultSet;
import com.datastax.driver.core.Row;
import com.datastax.driver.core.Session;
import com.datastax.driver.core.policies.RoundRobinPolicy;
import com.datastax.driver.core.policies.WhiteListPolicy;
import com.google.common.collect.ImmutableSet;

public class ByzantineClientTools {

	public static boolean print = false;
	public static boolean isWriteOption2 = true;
	public static String clientId = "clien1";
	private static Encryption ecryption = Encryption.getInstance();
	
	static public long getFreshTs() {
		return System.currentTimeMillis() * 1000;
	}
	
	public static class MetaVal{
		String clientName;
		String signautre;
		String ts;
		
		MetaVal(String ts, String clientName, String signature) {
			this.ts = ts;
			this.clientName = clientName;
			this.signautre = signature;
		}
	}
		
	// str = TS:clientName:Sign
	public static MetaVal parseString(String str){
		if (str == null) {
			return null;
		}
		
		int delimiterLoc = str.indexOf(":");
		if (delimiterLoc == -1) {
			return null;
		}
		
		String ts = str.substring(0, delimiterLoc);
		String rest = str.substring(delimiterLoc+1);
		
		delimiterLoc = rest.indexOf(":");
		if (delimiterLoc == -1) {
			return null;
		}
		
		String clientName = rest.substring(0, delimiterLoc);
		String sign = rest.substring(delimiterLoc+1);
		
		return new ByzantineClientTools.MetaVal(ts, clientName, sign);
	}
	
	public static String createMetaString(String ts, String clientName, String signature) {
		return String.format("%s:%s:%s", ts, clientName, signature);
	}
	
	// symmetricSigns = [ip]-[symmetricSign]:[ip]-[symmetricSign]:[ip]-[symmetricSign]:[ip]-[symmetricSign]
	// symmetricSign  = [key][values][metas (includes aSymmetric signatures)]
	static public String computeSymmetricSignature(String key, String values, String metas, List<InetAddress> hosts){
		
		byte[] data = (key+values+metas).getBytes();
		String symmetricSigns = "";
		
		for (InetAddress host : hosts) {
			String ip = host.getHostAddress();
			String nodeId = IpNodeBinding.ipToNodeId.get(ip);
			byte[] symmetricSign;
			try {
				symmetricSign = ecryption.signDataSym(data, Common.CLIENT_ID, nodeId);
				if (print) {
					System.out.println("Symmetric sign to: " + nodeId + " " + new String(symmetricSign));
				}
			} catch (Exception e) {
				System.out.printf("Error signing symmetric sign ip:%s client:%s node:%s error:%s" ,ip,Common.CLIENT_ID, nodeId,e.getMessage());
				continue;
			}
			
			if (symmetricSign == null) {
				System.out.println("Symmetric sign is null to: " + nodeId);
				return null;
			}
			
			if (!symmetricSigns.isEmpty()){
				symmetricSigns += ":";
			}
			
			symmetricSigns += (ip + "-" + new String(symmetricSign)); 
		}
		
		if (print)
			System.out.println("symmetricSigns: " + symmetricSigns);
		
		return symmetricSigns;
	}
	
	static public byte[] computeStoreSignature(String key, String value, long ts){
		// Compute signature
		byte[] sign = null;
		try 
		{
			sign = ecryption.signData((key + value + ts).getBytes());
			if (print) {
				System.out.println("Signed: " + new String(sign));
				System.out.println(Encryption.alias + " " + key + " " + value + " " + ts);
				//System.out.println(ecryption.verifyData("clien1", (key + value + ts).getBytes(),sign));
			}
		}
		catch (Exception e)
		{
			System.out.println(e.getMessage());
			return null;
		}
		
		return sign;
	}
	
	static public String getNodesIPs(Collection<String> ips) {
		if (ips == null) {
			return "";
		}
		
		String nodes = "";
		
		for (String ip : ips) {
			if (nodes.isEmpty()) {
				nodes = ip;
			} else {
				nodes += ":" + ip;
			}
		}
		
		return nodes;
	}
	
	public static String concatNodesIps(String old, Collection<String> newL){
		return concatNodesIps(old, getNodesIPs(newL));
	}
	
	public static String concatNodesIps(String old, String newS){
		if (newS == null || newS.isEmpty()) {
			return old;
		}
		
		if (old.isEmpty()) {
			old = newS;
		} else { 
			old += ":" + newS;
		}
		
		return old;
	}
	
	static public int validStoreAcks(ResultSet results, byte[] data, Set<String> ips, int stopVerifyingAfter){
		return validStoreAcksNodes(results, data, ips, stopVerifyingAfter).size();
	}
	
	static public Set<String> validStoreAcksNodes(
			ResultSet results, 
			byte[] data, 
			Set<String> ips,
			int stopVerifyingAfter){
		Set<String> nodes = new HashSet<String>();
		
		// Check nodes signatures
		for (Row row : results) {
			if (print)
				System.out.println("Got a signatue ");
			
			ByteBuffer blobSign = row.getBytes(0);
			byte[] signR = new byte[blobSign.remaining()];
			blobSign.get(signR);
			
			String node = row.getString(1);
			
			if (isWriteOption2 && ips != null) {
				String nodeAddr = row.getString(2);
				ips.add(nodeAddr);
				if (print)
					System.out.println(nodeAddr);
			}
			
			if (print) {
				System.out.println("Verifying sinature on data: " + new String(data));
			}
			
			boolean check = false;
			try {
				if (Common.isMACSignatures){
					check = ecryption.verifySymData(data, signR, clientId, node);
				} else {
					check = ecryption.verifyData(node, data, signR);
				}
			} catch (Exception e) {
				if (print)
					System.out.println(e.getMessage());
				continue;
			}
			
			if (print)
				System.out.println(
					node + " : " + 
					new String(signR) + "  " +
					(check ? "Verified" : "Verfication failed"));
			
			if (check) {
				nodes.add(node);
				
				if (nodes.size() >= stopVerifyingAfter){
					break;
				}
			}
		}
		
		return nodes;
	}
	
	// range - values indexing starting from 0 to range - [0,range)
	private static ParsedRowData getSignedData(String key, Row row, int range){
		String sign = "";
		String vals = "";
		for (int i = 0; i < range; ++i) {
			String metaString = row.getString(Common.META_COLUMN_PREFIX + i);
			if (metaString == null) {
				if (print) 
					System.out.printf("metaString %d not found - Might be a not found result.\n", i);
				continue;
			}
			
			MetaVal meta = parseString(metaString);
			if (meta == null) {
				if (print) {
					System.out.println("Could not parse meta string.");
				}
				return null;
			}
			
			sign += meta.signautre;
			
			String val = row.getString(Common.VALUE_COLUMN_PREFIX + i);
			if (val != null) {
				vals += val;
			}
		}
		
		ParsedRowData result = new ParsedRowData();
		
		// If all is empty, might be a "not found" message
		if (sign.isEmpty()) {
			result.signedData = Common.EMPTY_MESSAGE;
			result.hval = "";
		} else {
			result.signedData = sign;
			result.hval = computeCassandraHash(vals);
		}
		
		return result;
	}
	
	// TODO: eliminated this duplication
	private static ParsedRowData getSignedData(String key, Row row, Set<Integer> valuesNumbers){
		String sign = "";
		String vals = "";
		for (int i : valuesNumbers) {
			String metaString = row.getString(Common.META_COLUMN_PREFIX + i);
			if (metaString == null) {
				if (print) 
					System.out.printf("metaString %d not found - Might be a not found result.\n", i);
				continue;
			}
			
			MetaVal meta = parseString(metaString);
			if (meta == null) {
				if (print) {
					System.out.println("Could not parse meta string.");
				}
				return null;
			}
			
			sign += meta.signautre;
			
			String val = row.getString(Common.VALUE_COLUMN_PREFIX + i);
			if (val != null) {
				vals += val;
			}
		}
		
		ParsedRowData result = new ParsedRowData();
		
		// If all is empty, might be a "not found" message
		if (sign.isEmpty()) {
			result.signedData = Common.EMPTY_MESSAGE;
			result.hval = "";
		} else {
			result.signedData = sign;
			result.hval = computeCassandraHash(vals);
		}
		
		return result;
	}
	
	//@Nullable - return null if non-valid signature
	// range - values indexing starting from 0 to range - [0,range)
	private static String checkAndGetDataSignatureAll(String key, Row row, int range){
		// Get all values signatures and check those that are in valueNumbers
		String sign = "";
		for (int i = 0; i < range; ++i) {
			String metaString = row.getString(Common.META_COLUMN_PREFIX + i);
			
			if (metaString == null) {
				if (print) 
					System.out.printf("metaString %d not found - Might be a not found result.\n", i);
				continue;
			}
			
			MetaVal meta = parseString(metaString);
			if (meta == null) {
				if (print) {
					System.out.println("Could not parse meta string.");
				}
				return null;
			}
			
			String valSign 		= meta.signautre;
			String clientName 	= meta.clientName;
			String ts			= meta.ts;
			
			sign += valSign;

			String val  	    = row.getString(Common.VALUE_COLUMN_PREFIX + i);
			if (val == null) {
				return null;
			}
			
			if (print) {
				System.out.println("Verifying sinature on key + val + ts: " + key + val + ts);
			}
			
			boolean check = false;
			try {
				check = ecryption.verifyData(clientName, (key + val + ts).getBytes(), valSign.getBytes());
			} catch (Exception e) {
				System.out.println(e.getMessage());
				return null;
			}
			
			if (check == false){
				return null;
			}
			
			if (print) {
				System.out.println(
					String.format(
							"%s %s %s %s %s %s",
							key,
							val, 
							valSign,
							clientName, 
							ts,
							(check ? 
									"Verified Client Signature for val " + i : 
									"Verfication of Client Signature failed")));
			}
		}
		
		// If all is empty, might be a "not found" message
		if (sign.isEmpty()) {
			return Common.EMPTY_MESSAGE;
		}
		
		return sign;
	}
	
	@Deprecated
	private static String checkAndGetDataSignatureAllExact3Vals(String key, Row row, int range){
		String metaString0 = row.getString(Common.META_COLUMN_PREFIX + 0);
		String metaString1 = row.getString(Common.META_COLUMN_PREFIX + 1);
		String metaString2 = row.getString(Common.META_COLUMN_PREFIX + 2);
		
		if (metaString0 == null || metaString1 == null || metaString2 == null) {
			// Might be a "not found" message
			if (print) {
				System.out.println("Not found result.");
			}
			return Common.EMPTY_MESSAGE;
		}
		
		MetaVal meta0 = parseString(metaString0);
		MetaVal meta1 = parseString(metaString1);
		MetaVal meta2 = parseString(metaString2);

		String sign0 		= meta0.signautre;
		String sign1 		= meta1.signautre;
		String sign2 		= meta2.signautre;
		String clientName0 	= meta0.clientName;
		String clientName1 	= meta1.clientName;
		String clientName2 	= meta2.clientName;
		String ts0 			= meta0.ts;
		String ts1 			= meta1.ts;
		String ts2 			= meta2.ts;
		String val0 		= row.getString(Common.VALUE_COLUMN_PREFIX + 0);
		String val1 		= row.getString(Common.VALUE_COLUMN_PREFIX + 1);
		String val2 		= row.getString(Common.VALUE_COLUMN_PREFIX + 2);

		
		if (print) {
			System.out.println("should not run");
		}
		
		boolean check = false;
		try {
			check = ecryption.verifyData(clientName0, (key + val0 + ts0).getBytes(), sign0.getBytes());
			check = check && ecryption.verifyData(clientName1, (key + val1 + ts1).getBytes(), sign1.getBytes());
			check = check && ecryption.verifyData(clientName2, (key + val2 + ts2).getBytes(), sign2.getBytes());
		} catch (Exception e) {
			System.out.println(e.getMessage());
			return null;
		}

		if (print) {
			System.out.println(
				String.format(
						"%s %s %s %s %s %s",
						key,
						val0 + " " + val1 + " " + val2 ,
						sign0 + " " + sign1 + " " + sign2 ,
						clientName0 + " " + clientName1 + " " +clientName2 ,
						ts0 + " " + ts1 + " " + ts2 ,
						(check ? 
								"Verified Client Signature" : 
								"Verfication of Client Signature failed")));
		}
		
		if (check == false){
			return null;
		}
			
		return sign0 + sign1 + sign2;
	}
	
	//@Nullable - return null if non-valid signature
	private static String checkAndGetDataSignatureOneVal(String key, Row row, int valNumber){
		String metaString0 = row.getString(Common.META_COLUMN_PREFIX + 0);
		String metaString1 = row.getString(Common.META_COLUMN_PREFIX + 1);
		String metaString2 = row.getString(Common.META_COLUMN_PREFIX + 2);
		
		if (metaString0 == null || metaString1 == null || metaString2 == null) {
			// Might be a "not found" message
			if (print) {
				System.out.println("Not found result.");
			}
			return Common.EMPTY_MESSAGE;
		}
				
		MetaVal meta0 = parseString(metaString0);
		MetaVal meta1 = parseString(metaString1);
		MetaVal meta2 = parseString(metaString2);

		String sign0 		= meta0.signautre;
		String sign1 		= meta1.signautre;
		String sign2 		= meta2.signautre;
		
		String metaString 	= row.getString(Common.META_COLUMN_PREFIX + valNumber);
		MetaVal meta 		= parseString(metaString);
		String sign 		= meta.signautre;
		String clientName 	= meta.clientName;
		String ts			= meta.ts;
		String val  		= row.getString(Common.VALUE_COLUMN_PREFIX + valNumber);

		boolean check = false;
		try {
			check = ecryption.verifyData(clientName, (key + val + ts).getBytes(), sign.getBytes());
		} catch (Exception e) {
			System.out.println(e.getMessage());
			return null;
		}

		if (print) {
			System.out.println(
				String.format(
						"%s %s %s %s %s %s",
						key,
						val, 
						sign0 + sign1 + sign2,
						clientName, 
						ts,
						(check ? 
								"Verified Client Signature" : 
								"Verfication of Client Signature failed")));
		}
		
		if (check == false){
			return null;
		}
			
		return sign0 + sign1 + sign2;
	}
	
	private static boolean checkOneValSig(String key, String val, MetaVal meta){
		if (val == null || meta == null || key == null) {
			if (print)
				System.out.println("checkOnceValSig Got null");
			return false;
		}
		
		String valSign 		= meta.signautre;
		String clientName 	= meta.clientName;
		String ts			= meta.ts;
	
		if (print) {
			System.out.println("Verifying sinature on key + val + ts: " + key + val + ts);
		}
		
		try {
			boolean res = ecryption.verifyData(clientName, (key + val + ts).getBytes(), valSign.getBytes());
			
			if (res == false && print){
				System.out.println(clientName + " " + key + " " +  val + " " +  ts + " " + valSign );
			}
			
			return res;
		} catch (Exception e) {
			System.out.println(e.getMessage());
			return false;
		}
	}
	
	//@Nullable - return null if non-valid signature
	// range - values indexing starting from 0 to range - [0,range)
	private static String checkAndGetDataSignature(String key, Row row, Set<Integer> valueNumbers, int range){
		// Get all values signatures and check those that are in valueNumbers
		String sign = "";
		for (int i = 0; i < range; ++i) {
			String metaString = row.getString(Common.META_COLUMN_PREFIX + i);
			
			if (metaString == null) {
				if (print) 
					System.out.printf("metaString %d not found - Might be a not found result.\n", i);
				continue;
			}
			
			MetaVal meta = parseString(metaString);
			if (meta == null) {
				if (print) {
					System.out.println("Could not parse meta string.");
				}
				return null;
			}
			
			sign += meta.signautre;
			
			// check value if required
			if (valueNumbers.contains(i)) {
				String val  		= row.getString(Common.VALUE_COLUMN_PREFIX + i);
				
				boolean check = checkOneValSig(key, val, meta);
				if (check == false){
					return null;
				}
				
				if (print) {
					System.out.println(
						String.format(
								"%s %s %s %s %s %s",
								key,
								val, 
								meta.signautre,
								meta.clientName, 
								meta.ts,
								(check ? 
										"Verified Client Signature" : 
										"Verfication of Client Signature failed")));
				}
			}
		}
		
		// If all is empty, might be a "not found" message
		if (sign.isEmpty()) {
			return Common.EMPTY_MESSAGE;
		}
		
		return sign;
	}
	
	static class NodeState{
		public String nodeIp;
		public boolean isCorrect;
		
		public NodeState(String ip, boolean state){
			this.nodeIp = ip;
			isCorrect = state;
		}
		
		public static NodeState createCorrect(String ip){
			return new NodeState(ip, true);
		}
		
		public static NodeState createBadState(String ip){
			return new NodeState(ip, false);
		}
	}
	
	private static String getNodeIp(String nodeSign) {
		if (nodeSign == null) return null;
		String[] signData = nodeSign.split(":");
		if (signData.length != 3) {
			if (print)
				System.out.println("getNodeIp Got wrong structre: " + nodeSign);
			
			return null;
		}
		return signData[2];
	}
	
	// Validates read ACK
	// Returns the node IP or null if bad signature
	private static NodeState isNodeSignValid(
			String signedData, 
			String nodeSign, 
			String key, 
			String readTS, 
			boolean expectWriteBacks,
			String hvals){
		int requiredFields = 3;
		boolean isWriteBack = false;
		
		if (expectWriteBacks && nodeSign.startsWith(Common.WRITE_BACK_MESSAGE)){
			isWriteBack = true;
			requiredFields++;
		}

		String[] signData = nodeSign.split(":");
		if (signData.length != requiredFields) {
			if (print)
				System.out.println("Got wrong node signature structre: " + nodeSign);
			
			if (signData.length > 1) {
				return NodeState.createBadState(signData[signData.length-1]);
			}
			
			return null;
		}
		
		String nodeName 	= signData[requiredFields - 3];
		String nodeSign1 	= signData[requiredFields - 2];
		String nodeIP 		= signData[requiredFields - 1];
		
		boolean checkNodeSign = false;
		String data = String.format("%s:%s:%s:%s",key,hvals,signedData,readTS);
		if (isWriteBack) {
			data = Common.WRITE_BACK_MESSAGE + ":" + data;
		}
		
		try {
			if (Common.isMACSignatures){
				checkNodeSign = 
						ecryption.verifySymData(
								data.getBytes(), 
								nodeSign1.getBytes(), 
								clientId, 
								nodeName);
			} else {
				checkNodeSign = 
						ecryption.verifyData(
							nodeName, 
							data.getBytes(), 
							nodeSign1.getBytes());
			}
		} catch (Exception e) {
			if (print)
				System.out.println(e.getMessage());
			return NodeState.createBadState(nodeIP);
		}
		
		if (print)
			System.out.println(
				nodeSign + 
				(checkNodeSign ? 
						" Verified Node Signature from " : 
						" Verfication of Node Signature failed ") + nodeIP);
		
		return (checkNodeSign == true ? 
				NodeState.createCorrect(nodeIP) : 
				NodeState.createBadState(nodeIP));
	}
	
//	public static int validSignaturesAll(Row row, String key, int range, int stopVerifyingAfter, String readTS) {
//		// Checks the data signature (signed by a client)
//		String signedData = checkAndGetDataSignatureAll(key, row, range);
//		return validSignaturesAux(row, key, signedData, stopVerifyingAfter, readTS, null, false).getKey().size();
//	}
	
	private static class ParsedRowData {
		public String signedData;
		public String hval;
	}
	
	// Returns <goodSigners, badSigners>
	public static Entry<Set<String>, Set<String>> validSignaturesAllS(Row row, String key, int range, int stopVerifyingAfter, String readTS) {
		// Skipping verification, using majority
		// Checks the data signature (signed by a client)
		//String signedData = checkAndGetDataSignatureAll(key, row, range);
		ParsedRowData data = getSignedData(key, row, range); 
		return validSignaturesAux(row, key, data.signedData, stopVerifyingAfter, readTS, null, false, data.hval);
	}
	
//	public static int validSignaturesOneVal(Row row, String key, int valNumber, int stopVerifyingAfter, String readTS) {
//		// Checks the data signature (signed by a client)
//		String signedData = checkAndGetDataSignatureOneVal(key, row, valNumber);
//		return validSignaturesAux(row, key, signedData, stopVerifyingAfter, readTS, null, false).getKey().size();
//	}
	
//	public static int validSignatures(Row row, String key, Set<Integer> valuesNumbers, int range, int stopVerifyingAfter, String readTS) {
//		// Checks the data signature (signed by a client)
//		String signedData = checkAndGetDataSignature(key, row, valuesNumbers, range);
//		return validSignaturesAux(row, key, signedData, stopVerifyingAfter, readTS, null, false).getKey().size();
//	}
	
	// Returns <goodSigners, badSigners>
	public static Entry<Set<String>, Set<String>> validSignaturesS(
			Row row, 
			String key, 
			Set<Integer> valuesNumbers, 
			int range,
			int stopVerifyingAfter,
			String readTS) {
		// Skipping verification, using majority
		// Checks the data signature (signed by a client)
		//String signedData = checkAndGetDataSignature(key, row, valuesNumbers, range);
		ParsedRowData data = getSignedData(key, row, valuesNumbers); 
		return validSignaturesAux(row, key, data.signedData, stopVerifyingAfter, readTS, null, false, data.hval);
	}
	
	// Returns <goodSigners, badSigners>
	public static Entry<Set<String>, Set<String>> validOnlyNodesSignaturesS(Row row, String key, Set<Integer> valuesNumbers, int range, int stopVerifyingAfter, String readTS) {
		// Checks the data signature (signed by a client)
		ParsedRowData data = getSignedData(key, row, range); 
		return validSignaturesAux(row, key, data.signedData, stopVerifyingAfter, readTS, null, false, data.hval);
	}
	
	// Looks for the row that has the resolved mark
	// @ Assume proxy verifies
	// @ Returns it if validation checks out
	private static ResultsWithResolving getResolvedRow(Collection<Row> rows, String key, int range, int requiredAnswers, String readTS) {
		// A complete solution will check that there is exactly one resolved row
		for (Row row : rows) {
			String nodesSignatures = row.getString(Common.NODES_SIGNATURES_COLUMN);
			if (nodesSignatures == null) {
				continue;
			}
			
			if (nodesSignatures.startsWith(Common.RESOLVED_PREFIX)){
				nodesSignatures = nodesSignatures.substring(Common.RESOLVED_PREFIX.length());
				
				ParsedRowData data = getSignedData(key, row, range);
				Entry<Set<String>, Set<String>> results = 
						validSignaturesAux(row, key, data.signedData, requiredAnswers, readTS, nodesSignatures, true, data.hval);
				
				if (results == null) return null;
				
				ResultsWithResolving result = new ResultsWithResolving();
				result.goodSigners = results.getKey();
				result.badSigners = results.getValue();
				
				int validSignatures = result.goodSigners.size();
				if (validSignatures >= requiredAnswers) {
					result.resolvedRow = row;
				}
				
				return result;
			}
		}
		return null;
	}
	
	private static boolean isNewerOrSame(Row row1, Row row2, int field){
		String metaString1 = row1.getString(Common.META_COLUMN_PREFIX + field);
		String metaString2 = row2.getString(Common.META_COLUMN_PREFIX + field);
		
		// Null is an indication for not found
		if ((metaString1 == null && metaString2 == null) ||
		    (metaString1 != null && metaString2 == null) ){
			return true;
		}
		
		if (metaString1 != null && metaString2 == null) return false;
		
		
		MetaVal meta1 = parseString(metaString1);
		MetaVal meta2 = parseString(metaString2);
		if (meta1 == null || meta2 == null) return false;
		
		String ts1s = meta1.ts;
		String ts2s	= meta2.ts;
		
		Long ts1 = Long.parseLong(ts1s);
		Long ts2 = Long.parseLong(ts2s);
		
		if (ts1 > ts2) return true;
		if (ts1 < ts2) return false;
		
		// ts is the same, compare values
		String val1 = row1.getString(Common.VALUE_COLUMN_PREFIX + field);
		String val2 = row2.getString(Common.VALUE_COLUMN_PREFIX + field);
		if (val1 == null || val2 == null) return false;
		
		if (val2.compareTo(val1) >= 0) {
			return true;
		} else {
			return false;
		}
	}
	
	// True if row1 >= row2
	private static boolean isNewerOrSame(Row row1, Row row2, boolean shouldReadAll, int range, Set<Integer> fieldsNumbers) {
		if (shouldReadAll) {
			for (int i = 0; i < range; ++i) {
				if (!isNewerOrSame(row1, row2, i)){
					return false;
				}
			}
		} else {
			for (int i : fieldsNumbers) {
				if (!isNewerOrSame(row1, row2, i)){
					return false;
				}
			}
		}
		
		return true;
	}
	
	public static class ResultsWithResolving{
		public Set<String> goodSigners;
		public Set<String> badSigners;
		public Row resolvedRow = null;
	}
	
	public static Row getResolvedRowIfCorrect(
			boolean shouldReadAll,
			String key,
			int range,
			Collection<Row> rows,
			int requiredAnswers,
			String readTS,
			Set<Integer> fieldsNumbers) {
		
		ResultsWithResolving result = getNodesAndResolvedRowIfCorrect(shouldReadAll, key, range, rows, requiredAnswers, readTS, fieldsNumbers);
		if (result == null) {
			return null;
		} else {
			return result.resolvedRow;
		}
	}
	
	public static ResultsWithResolving getNodesAndResolvedRowIfCorrect(
			boolean shouldReadAll,
			String key,
			int range,
			Collection<Row> rows,
			int requiredAnswers,
			String readTS,
			Set<Integer> fieldsNumbers) {

		// Get and validate the resolved row
		ResultsWithResolving resolvedResult = getResolvedRow(rows, key, range, requiredAnswers, readTS);
		if (resolvedResult == null || resolvedResult.resolvedRow == null) {
			if (print) {
				System.out.println("getResolvedRow is null");
			}
			return resolvedResult;
		}
		
		// We take off the row and put it back only if everything is ok.
		Row resolvedRow = resolvedResult.resolvedRow;
		resolvedResult.resolvedRow = null;
		
		int validated = 0;
		for (Row eRow : rows) {
			// Check that it is not a resolved row
			String nodesSignatures = eRow.getString(Common.NODES_SIGNATURES_COLUMN);
			if (nodesSignatures == null) {
				if (print) {
					System.out.println("can't find nodesSignatures in getResolvedRowIfCorrect");
				}
				continue;
			}
			
			if (nodesSignatures.startsWith(Common.RESOLVED_PREFIX)){
				continue;
			}
			
			// Validate it's signature
			ParsedRowData data = getSignedData(key, eRow, range); 
			Entry<Set<String>, Set<String>> result = validSignaturesAux(eRow, key, data.signedData, 1, readTS, null, false, data.hval);
			
			if (result.getKey().size() < 1) {
				if (print) {
					System.out.println("row validation failed");
				}
				resolvedResult.badSigners.add(getNodeIp(data.signedData));
				continue;
			}
			
			// Validate it is not newer than resolved
			if (isNewerOrSame(resolvedRow, eRow, shouldReadAll, range, fieldsNumbers)) {
				validated++;
				if (print) {
					System.out.println("Resolved row is newer  or same than checkd row");
				} 
			} else {
				if (print) {
					System.out.println("Resolved row is older than checkd row");
				}
				return resolvedResult;
			}
			
			// Stop after requiredAnswers achieved
			if (validated >= requiredAnswers) {
				resolvedResult.resolvedRow = resolvedRow;
				return resolvedResult;
			}
		}
		
		if (print) {
			System.out.println("Couldn't validate the resolving, validated: " + validated);
		}
		return resolvedResult;
	}
	
	// Aggregates results for results where each row is a node reply
	// Returns <goodSigners, badSigners>
	public static Entry<Set<String>, Set<String>> validOnlyNodesSignaturesS(List<Row> rows, String key, int range, int stopVerifyingAfter, String readTS) {
		Set<String> goodSigners = new HashSet<String>(); 
		Set<String> badSigners = new HashSet<String>();
		
		for (Row row : rows) {
			// Checks the data signature (signed by a client)
			ParsedRowData data = getSignedData(key, row, range); 
			Entry<Set<String>, Set<String>> result = validSignaturesAux(row, key, data.signedData, 1, readTS, null, false, data.hval);
			
			if (result.getKey().size() + result.getValue().size() != 1){
				if (print)
					System.out.println("Too many results on one row");
			}
			
			goodSigners.addAll((result.getKey()));
			if (goodSigners.size() >= stopVerifyingAfter){
				break;
			}
			badSigners.addAll((result.getValue()));
		}
		
		return new AbstractMap.SimpleEntry<Set<String>, Set<String>>(goodSigners, badSigners);
	}
	
	public static class NodesStatistics{
		Set<String> goodNodes;
		Set<String> badNodes;
		
		int goodNodesNum;
	}
	
//	public static Map.Entry<Set<String>, Set<String>> validSignatures(Row row, int valNumber, String key, int range, int stopVerifyingAfter, String readTS) {
//		// Checks the data signature (signed by a client)
//		String signedData;
//		if (valNumber == -1){
//			signedData = checkAndGetDataSignatureAll(key, row, range);
//		} else {
//			signedData = checkAndGetDataSignatureOneVal(key, row, valNumber);
//		}
//		
//		return validSignaturesAux(row, key, signedData, stopVerifyingAfter, readTS, null, false);
//	}
	
	// Return <goodSigners, badSigners>
	public static Map.Entry<Set<String>, Set<String>> validSignaturesAux(
			Row row, 
			String key, 
			String signedData,
			int stopVerifyingAfter,
			String readTS,
			String nodesSignaturesInput,
			boolean expectWriteBacks,
			String hvals) {
		if (signedData == null)  {
			return null;
		}
		
		String nodesSignatures = nodesSignaturesInput;
		if (nodesSignatures == null) {
			nodesSignatures = row.getString(Common.NODES_SIGNATURES_COLUMN);
		}
		
		if (nodesSignatures == null || nodesSignatures == "") {
			if (print)
				System.out.println("No Nodes signatures");
			return null;
		}
		
		if (print)
			System.out.println("Verifying all signatures on " + signedData + " and hval: " + hvals);
		
		// Check the nodes signatures
		Set<String> goodSigners = new HashSet<String>(); 
		Set<String> badSigners = new HashSet<String>();
		String[] signs = nodesSignatures.split(",");
		for (String nodeSign : signs) {
			NodeState state = isNodeSignValid(signedData, nodeSign, key, readTS, expectWriteBacks, hvals);
			
			// Mark this proxy as bad?
			if (state == null)
				continue;
			
			if (state.isCorrect) {
				goodSigners.add(state.nodeIp);
				if (goodSigners.size() >= stopVerifyingAfter) {
					break;
				}
			} else {
				badSigners.add(state.nodeIp);
			}
		}
		
		return new AbstractMap.SimpleEntry<Set<String>, Set<String>>(goodSigners, badSigners);
	}
	
//	public static Map.Entry<List<String>, List<String>> validNodesAnswers(
//			List<Row> rows, 
//			String key,
//			int range, 
//			String readTS) {
//
//		List<String> goodSigners = new LinkedList<String>(); 
//		List<String> badSigners = new LinkedList<String>();
//		
//		for (Row row : rows) {
//			String signedData = getSignedData(key,row,range);
//			if (signedData == null)  {
//				if (print)
//					System.out.println("No signedData");
//				return null;
//			}
//		
//			String nodesSignature = row.getString(Common.NODES_SIGNATURES_COLUMN);
//			if (nodesSignature == null || 
//				nodesSignature.isEmpty()) {
//				if (print)
//					System.out.println("No Nodes signatures");
//				return null;
//			}
//		
//			NodeState state = isNodeSignValid(signedData, nodesSignature, key, readTS, false);
//			// Mark this proxy as bad?
//			if (state == null)
//				continue;
//			
//			if (state.isCorrect) {
//				goodSigners.add(state.nodeIp);
//			} else {
//				badSigners.add(state.nodeIp);
//			}
//		}
//		
//		return new AbstractMap.SimpleEntry<List<String>, List<String>>(goodSigners, badSigners);
//	}
	

	
	public static String injectKeyData(
			String key, 
			String ts, 
			String clientName, 
			String blackList,
			boolean shouldReadAll,
			Set<Integer> fieldsNumbers) {
		String injectedString = key + ";" + ts + ";";
		
		if (shouldReadAll) {
			injectedString += Common.REQUEST_ALL_FIELDS;
		} else {
			boolean isFirst = true;
			for (int i : fieldsNumbers) {
				if (!isFirst) {
					injectedString += ":";
				} 
				
				injectedString += i;
				
				isFirst = false;
			}
		}
		
		if (clientName != null) {
			injectedString += ";" + clientName;
			
			if (blackList != null) {
				injectedString += ";" + blackList;
			}
		}
		
		if (print)
			System.out.println("InjectedString: " + injectedString);
		
		return injectedString;
	}

	public static String listToStringWithSeperator(Collection<String> blackSet) {
		if (blackSet == null) 
			return null;
		
		if (blackSet.isEmpty()) 
			return "";
		
		String firstBlack = blackSet.iterator().next();
		int size = 0;
		if (firstBlack == null) {
			size = 1;
		} else {
			size = firstBlack.length();
		}
		
		StringBuilder sb = new StringBuilder(blackSet.size()*size);
		
		for (String s : blackSet){
			if (sb.length() > 0){
				sb.append(":");
			}
			
			sb.append(s);
		}

		return sb.toString();
	}
	
	public static class Resolved{
		public Map<String, String> mapping;
		public String allSignatures;
		public Set<String> updatedReplicas;
		
		public Resolved(
				Map<String, String> mapping, 
				String allSignatures,
				Set<String> updatedReplicas) {
			this.mapping = mapping;
			this.allSignatures = allSignatures;
			this.updatedReplicas = updatedReplicas;
		}
	}
	
	// Assume that every row has all of the columns
	public static Resolved resolver(List<Row> versions, String key, int range){
		if (print) {
			System.out.println("*** Resolving versions");
		}
		
		Set<Integer> badVersions = new HashSet<Integer>();
		Map<String, String> resolved = new HashMap<String,String>();
		String allSignatures = "";
		
		Integer resolvingColumn = 0;
		while (resolvingColumn < range) {
			String column = resolvingColumn.toString();
			
			if (print) {
				System.out.println("Solving column: " + column);
			}
			
			long maxTS = Long.MIN_VALUE;
			int selectedVersion = -1;
			MetaVal selectedMeta = null;
			String selectedMetaString = null;
			String selectedValue = null;
			
			// Get the version with the latest timestamp
			for (int versionNum = 0; versionNum < versions.size(); ++versionNum) {
				Row curVersion = versions.get(versionNum);
				if (badVersions.contains(versionNum)) {
		        	if (print) {
		        		System.out.println("Skiping badVersions: " + versionNum);
		        	}
					continue;
				}
				
				String metaString 	= curVersion.getString(Common.META_COLUMN_PREFIX + column);
				String value 		= curVersion.getString(Common.VALUE_COLUMN_PREFIX + column);
				MetaVal meta 		= parseString(metaString);
				if (meta == null || value == null) {
					if (print)
						System.out.println("Got wrong meta string: " + metaString + " or val is null: " + value);
					badVersions.add(versionNum);
					continue;
				}
				
				Long curTs 		= Long.parseLong(meta.ts);
				
				if ((curTs > maxTS) || ((curTs == maxTS) && (selectedValue.compareTo(value) > 0))) {
					maxTS = curTs;
					selectedVersion = versionNum;
					selectedMeta = meta;
					selectedMetaString = metaString;
					selectedValue = value;
					if (print) {
		        		System.out.println("Current best version: " + versionNum + " ts: " + maxTS);
		        	}
				}
			}
			
			if (selectedVersion == -1) {
				if (print) {
		    		System.out.println("Can't find good version, skipping column: " + column);
		    	}
				++resolvingColumn;
				continue;
			}
			
			// Verifying version
			boolean verification = checkOneValSig(key, selectedValue, selectedMeta);
		
			if (verification){
				if (selectedValue.equals(Common.EMPTY_MESSAGE)) {
					if (print) {
			    		System.out.println("Empty message, not writing this back");
					}
				} else {
					resolved.put(Common.VALUE_COLUMN_PREFIX + column, selectedValue);
					resolved.put(Common.META_COLUMN_PREFIX + column, selectedMetaString);
				}
				if (print) {
		    		System.out.println("Signature verification success, selectedVersion= " + selectedVersion + " value " + selectedValue);
				}
			} else {
				if (print) 
		    		System.out.println("Signature verification failed, selectedVersion= " + selectedVersion);
					badVersions.add(selectedVersion);
					continue;
			}
				
			allSignatures += selectedMeta.signautre;
			++resolvingColumn;
		}
			
		Set<String> updatedReplicas = getUpdatedReplicas(versions, resolved, badVersions, range);
		return new Resolved(resolved, allSignatures, updatedReplicas);
	}
	
	private static Set<String> getUpdatedReplicas(List<Row> versions, Map<String, String> resolved, Set<Integer> badVersions, int range){
		Set<String> allReplicas = new HashSet<String>();
		for (Row row : versions) {
			String rowSign	= row.getString(Common.NODES_SIGNATURES_COLUMN);
			String ip = getNodeIp(rowSign);
			if (ip != null) allReplicas.add(ip);
		}
		
		Set<String> notUpdatedReplicas = new HashSet<String>();
		for (int i = 0; i< range; ++i){
			String val = resolved.get(Common.VALUE_COLUMN_PREFIX + i);
			String meta = resolved.get(Common.META_COLUMN_PREFIX + i);
			
			if (val == null || meta == null) continue;
			
			for (int version = 0; version < versions.size(); ++ version) {
				Row row = versions.get(version);
				String rowValue = row.getString(Common.VALUE_COLUMN_PREFIX + i);
				String rowMeta 	= row.getString(Common.META_COLUMN_PREFIX  + i);
				String rowSign	= row.getString(Common.NODES_SIGNATURES_COLUMN);
				
				if (badVersions.contains(versions) ||
					!val.equals(rowValue) || 
					!meta.equals(rowMeta)) {
					String ip = getNodeIp(rowSign);
					if (ip != null) notUpdatedReplicas.add(ip);
				}
			}
		}
		
		allReplicas.removeAll(notUpdatedReplicas);
		return allReplicas;
	}
	 
	public static Cluster createClusterConnectedToOneNode(InetSocketAddress addr){
		Collection<InetSocketAddress> whiteList = ImmutableSet.of(addr);
		
		return Cluster.builder()
				.withLoadBalancingPolicy(
						new WhiteListPolicy(new RoundRobinPolicy(), whiteList))
				.addContactPointsWithPorts(whiteList)
				.build();
	}
	
	public static class PerNodeConnection{
		public List<InetAddress> hosts;
		public List<Cluster> clusters;
		public Map<InetAddress, Session> sessions;
		
		public PerNodeConnection(List<Cluster> clusters, Map<InetAddress, Session> sessions, List<InetAddress> hosts) {
			this.clusters = clusters;
			this.sessions = sessions;
			this.hosts = hosts;
		}
		
		public Session getRandomSession(Set<InetAddress> blackList){
			if (hosts.isEmpty()) {
				System.err.println("Hosts is empty :(");
				return null;
			}
			
			int random = new Random().nextInt(hosts.size());
			InetAddress host = hosts.get(random);
			
			while (blackList.contains(host)) {
				random = (random + 1) % hosts.size();
				host = hosts.get(random);
			}
			
			return sessions.get(host);
		}
		
		public Session getSession(InetAddress addr) {
			return sessions.get(addr);
		}
	}
	
	public static void closeAllPerNodeConnection(PerNodeConnection perNodeConnection) {
		for (Session session : perNodeConnection.sessions.values()){
			session.close();
		}
		
		for (Cluster cluster : perNodeConnection.clusters){
			cluster.close();
		}
	}
	
	public static String buildWriteStringToExtractTs(){
		return ",,true";
	}
	
	public static String buildWriteInjectedString(
			int requiredAnswers, 
			String nodesIps, 
			boolean shouldInjectTimeStamps) {
		
		return String.format("%d,%s,%s", 
					requiredAnswers, 
					nodesIps,
					(shouldInjectTimeStamps ? "true" : "false")
				);
	}
	
	public static String computeCassandraHash(String text){
		try {
			MessageDigest m = MessageDigest.getInstance("MD5");
			byte[] digest = m.digest(text.getBytes());
			return new String(digest);
		} catch (NoSuchAlgorithmException e) {
			if (print) {
				System.out.println("[ronili]  computeCassandraHash fail " + e.getMessage());
			}
			return null;
		}
	}
}
