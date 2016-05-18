package com.yahoo.ycsb;

import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.Map.Entry;

import com.datastax.driver.core.ColumnDefinitions;
import com.datastax.driver.core.ConsistencyLevel;
import com.datastax.driver.core.ResultSet;
import com.datastax.driver.core.Row;
import com.datastax.driver.core.Session;
import com.datastax.driver.core.Statement;
import com.datastax.driver.core.exceptions.ReadTimeoutException;
import com.datastax.driver.core.exceptions.WriteTimeoutException;
import com.datastax.driver.core.querybuilder.Insert;
import com.datastax.driver.core.querybuilder.QueryBuilder;
import com.datastax.driver.core.querybuilder.Select;

import com.yahoo.ycsb.db.ByzantineClientTools.ResultsWithResolving;
import com.yahoo.ycsb.db.Common;
import com.yahoo.ycsb.db.ByzantineClientTools;
import com.yahoo.ycsb.db.ByzantineClientTools.PerNodeConnection;
import com.yahoo.ycsb.db.ByzantineClientTools.Resolved;

public class YCSBsubClient {

	private boolean debug;
	private Session session;
	private PerNodeConnection perNodeConnection;
	private ConsistencyLevel readConsistencyLevel;
	private ConsistencyLevel writeConsistencyLevel;
	
	public YCSBsubClient(
			Session session,
			ConsistencyLevel readConsistencyLevel,
			ConsistencyLevel writeConsistencyLevel, 
			boolean debug,
			PerNodeConnection perNodeConnection) {
		this.session = session;
		this.readConsistencyLevel = readConsistencyLevel;
		this.writeConsistencyLevel = writeConsistencyLevel;
		this.debug = debug;
		this.perNodeConnection = perNodeConnection;
	}

	@SuppressWarnings("unused")
	/*
	 * shouldReadAll - If true: Select all
	 * 				   If false: Select only those in fieldsNumbers
	 */
	private Statement createReadStatment(
			String table, 
			String key,
			Set<Integer> fieldsNumbers,
			boolean shouldReadAll) {
		Statement stmt;
		Select.Builder selectBuilder;

		// Build select query
		if (shouldReadAll) {
			selectBuilder = QueryBuilder.select().all();
		} else {
			selectBuilder = QueryBuilder.select();

			// Select requested values and meta.
			for (Integer fieldNumber : fieldsNumbers) {
				((Select.Selection) selectBuilder)
						.column(Common.META_COLUMN_PREFIX + fieldNumber)
						.column(Common.VALUE_COLUMN_PREFIX + fieldNumber);
			}

			// Select signatures column.
			((Select.Selection) selectBuilder)
					.column(Common.NODES_SIGNATURES_COLUMN);
		}

		// Select by key
		stmt = selectBuilder.from(table).where(
				QueryBuilder.eq(Common.KEY_COLUMN, key));

		stmt.setConsistencyLevel(readConsistencyLevel);

		return stmt;
	}

	// Translates the set of strings "field[i]" to set of integers [i].
	private static Set<Integer> getFieldsNumbers(Set<String> fields) {
		Set<Integer> fieldsNumbers = new HashSet<Integer>();
		for (String col : fields) {
			String fieldNumber = col.replaceAll("field", "");
			fieldsNumbers.add(Integer.parseInt(fieldNumber));
		}
		return fieldsNumbers;
	}
	
	private Row handleResultReadOption1(
			ResultSet rs,
			boolean shouldReadAll,
			String key,
			Set<Integer> fieldsNumbers,
			String readTS){
		
		// There are two options:
		// 1 row, fast read success.
		// 2f+2 <= rows, since resolving occurred.
		List<Row> rows = rs.all();
		
		if (readConsistencyLevel != ConsistencyLevel.QUORUM) {
			return rows.get(0);
		}
		
		if (debug) {
			System.out.println("Number of rows: " + rows.size());
		}
		
		Row row;
		if (rows.size() == 1) {
			row = rows.get(0);
			
			// Gets <goodSigners, badSigners>
			Entry<Set<String>, Set<String>> result = getResults(shouldReadAll, key, fieldsNumbers, row, Common.REQUIRED_SET_FOR_QUORUM, readTS);
			int validSignatures = result.getKey().size();
			
			if (validSignatures < Common.REQUIRED_SET_FOR_QUORUM) {
				if (debug)
					System.out.println("No REQUIRED_SET_FOR_QUORUM");
				return null;
			}
			
		// 1 resolved row REQUIRED_SET_FOR_QUORUM for quorum
		} else if (rows.size() >= Common.REQUIRED_SET_FOR_QUORUM + 1) {
			// row if resolved correctly and has REQUIRED_SET_FOR_QUORUM signatures
			row = ByzantineClientTools.getResolvedRowIfCorrect(shouldReadAll, key, Common.NUM_OF_FIELDS, rows, Common.REQUIRED_SET_FOR_QUORUM, readTS, fieldsNumbers);
		} else {
			return null;
		}
		
		return row;
	}
	
	private static ResultsWithResolving getResultsWithResolvingValidation(
			boolean shouldReadAll,
			String key,
			Set<Integer> fieldsNumbers,
			List<Row> rows,
			int requiredAnswers,
			String readTS) {
		
		if (rows.size() == 1) {
			Row row = rows.get(0);
			Entry<Set<String>, Set<String>> results = getResults(shouldReadAll, key, fieldsNumbers, row, requiredAnswers, readTS);
			if (results == null) {
				return null;
			}
			
			ResultsWithResolving result = new ResultsWithResolving();
			result.goodSigners = results.getKey();
			result.badSigners = results.getValue();
			result.resolvedRow = row;
			
			return result;
		} else if (rows.size() >= (requiredAnswers + 1)) {
			return ByzantineClientTools.getNodesAndResolvedRowIfCorrect(shouldReadAll, key, Common.NUM_OF_FIELDS, rows, requiredAnswers, readTS, fieldsNumbers);
		} 
		
		return null;
		
	}
	
	// Returns <goodSigners, badSigners>
	private static Entry<Set<String>, Set<String>> getResults(
			boolean shouldReadAll,
			String key,
			Set<Integer> fieldsNumbers,
			Row row,
			int stopVerifyingAfter,
			String readTS) {
		Entry<Set<String>, Set<String>> result;
		if (shouldReadAll) {
			result = ByzantineClientTools.validSignaturesAllS(
					row, key, Common.NUM_OF_FIELDS, stopVerifyingAfter,readTS);
		} else {
			result = ByzantineClientTools.validSignaturesS(
					row, key, fieldsNumbers, Common.NUM_OF_FIELDS, stopVerifyingAfter, readTS);
		}
		return result;
	}
	
	private Row handleResultReadOption2a(
			ResultSet rs,
			boolean shouldReadAll,
			String key,
			Set<Integer> fieldsNumbers,
			String table,
			String readTS){
		if (debug) {
			System.out.println("Using read option 2a");
		}
		
		if (readConsistencyLevel != ConsistencyLevel.QUORUM) {
			return rs.one();
		}
		
		// Should be only 1 row
		List<Row> rows = rs.all();

		// Gets <goodSigners, badSigners, row>
		ResultsWithResolving result = getResultsWithResolvingValidation(shouldReadAll, key, fieldsNumbers, rows, Common.REQUIRED_SET_FOR_QUORUM, readTS);
		if (result == null) {
			return null;
		}
		int validSignatures = result.goodSigners.size();
		
		Row resultRow = result.resolvedRow;
		if (resultRow == null || validSignatures < Common.REQUIRED_SET_FOR_QUORUM) {
			// This read isn't perfect
			resultRow = null;
			
			if (validSignatures < Common.REQUIRED_SET_FOR_RETRY){
				// Not enough answers for retry
				if (debug)
					System.out.println("No REQUIRED_SET_FOR_QUORUM");
				return null;
			}
			
			// Try to get more answers from same node
			Session sameNodeSession = perNodeConnection.getSession(
					rs.getExecutionInfo().getQueriedHost().getAddress());
			
			// Ask for answers not from "bad nodes" (They might be bad and it might be the proxy make them look bad)
			// For that case we will try a new proxy later (if required)
			Set<String> blackList = result.badSigners;
			int oldBlackListSize = 0;
			int retryNumber = 0;
			do {
				retryNumber++;

				Long 		ts 				= ByzantineClientTools.getFreshTs();
				String 		tsString 		= ts.toString();
				String 		blackListString = ByzantineClientTools.listToStringWithSeperator(blackList);
				String 		injectedKey 	= ByzantineClientTools.injectKeyData(key, tsString, Common.CLIENT_ID, blackListString, shouldReadAll, fieldsNumbers);
				Statement 	stmt 			= createReadStatment(table, injectedKey, fieldsNumbers, shouldReadAll);
				if (debug) {
					System.out.println(stmt.toString());
				}
				
				Results newResults = execute(sameNodeSession, stmt);
				if (newResults == null) return null;
				ResultSet newRs = newResults.rs;
				if (newRs == null || newRs.isExhausted()) return null;
				//
				List<Row> newRows = newRs.all();
				
				ResultsWithResolving newResult = getResultsWithResolvingValidation(
						shouldReadAll, 
						key, 
						fieldsNumbers, 
						rows,
						Common.REQUIRED_SET_FOR_QUORUM,
						tsString);
				
				int newValidSignatures = newResult.goodSigners.size();
				// Success
				if (newResult.resolvedRow != null && newValidSignatures >= Common.REQUIRED_SET_FOR_QUORUM){
					resultRow = newResult.resolvedRow;
					break;
				}
				// Big failure
				if (newValidSignatures < Common.REQUIRED_SET_FOR_RETRY){
					return null;
				}
				
				// Maybe can milk more
				oldBlackListSize = blackList.size();
				blackList.addAll(newResult.badSigners);
			} while ((retryNumber < Common.F) &&
					 (blackList.size() > oldBlackListSize));
		}
				
		return resultRow;
	}
	
	private Row handleResultReadOption2b(
			ResultSet rs,
			boolean shouldReadAll,
			String key,
			Set<Integer> fieldsNumbers,
			String table,
			Map<String, ByteIterator> results,
			String readTS) {
		
		if (rs.isExhausted()){
			return null;
		}
		
		if (readConsistencyLevel != ConsistencyLevel.QUORUM) {
			return rs.one();
		}
		
		// Might be 1 or 2f+ 1 rows
		List<Row> rows = rs.all();
		if (debug)
			System.out.println("Number of rows: " + rows.size());
		
		Entry<Set<String>, Set<String>> result = null;
		if (rows.size() == 1) {
			Row row = rows.get(0);
			result = getResults(shouldReadAll, key, fieldsNumbers, row, Common.REQUIRED_SET_FOR_QUORUM, readTS);
			int validSignatures = result.getKey().size();
			if (validSignatures >= Common.REQUIRED_SET_FOR_QUORUM) {
				return row;
			}
		} else if (rows.size() >= Common.REQUIRED_SET_FOR_QUORUM) {
			result = ByzantineClientTools.validOnlyNodesSignaturesS(
							rows, key, Common.NUM_OF_FIELDS, Common.REQUIRED_SET_FOR_QUORUM, readTS);
		} else {
			return null;
		}
		
		int validSignatures = result.getKey().size();

		if (validSignatures < Common.REQUIRED_SET_FOR_RETRY){
			// Not enough answers for retry
			if (debug)
				System.out.println("No REQUIRED_SET_FOR_QUORUM");
			return null;
		}
		
		Set<String> blackList = result.getValue();
		Session sameNodeSession = perNodeConnection.getSession(
				rs.getExecutionInfo().getQueriedHost().getAddress());

		int retryNumber = 0;
		int oldBlackListSize = 0;

		// Try to get more answers
		while ((retryNumber < Common.F) &&
			   (blackList.size() > oldBlackListSize)) {
			retryNumber++;
			
			Long 		ts 				= ByzantineClientTools.getFreshTs();
			String 		blackListString = ByzantineClientTools.listToStringWithSeperator(blackList);
			String 		injectedKey 	= ByzantineClientTools.injectKeyData(key, ts.toString(), Common.CLIENT_ID, blackListString, shouldReadAll, fieldsNumbers);
			Statement 	stmt 			= createReadStatment(table, injectedKey, fieldsNumbers, shouldReadAll);
			if (debug) {
				System.out.println(stmt.toString());
			}
			
			Results newResults = execute(sameNodeSession, stmt);
			if (newResults == null) return null;
			ResultSet newRs = newResults.rs;
			if (newRs == null || newRs.isExhausted()) return null;
			
			List<Row> newRows = newRs.all();
			// Big failure
			if (newRows.size() < Common.REQUIRED_SET_FOR_QUORUM) {
				return null;
			}
				
			Entry<Set<String>, Set<String>> newResult = 
					ByzantineClientTools.validOnlyNodesSignaturesS(rows, key, Common.NUM_OF_FIELDS, Common.REQUIRED_SET_FOR_QUORUM, readTS);
			validSignatures = newResult.getKey().size();
			
			// Success
			if (validSignatures >= Common.REQUIRED_SET_FOR_QUORUM){
				rows = newRows;
				break;
			}
			// Big failure
			if (validSignatures < Common.REQUIRED_SET_FOR_RETRY){
				return null;
			}
			
			// Maybe can milk more
			oldBlackListSize = blackList.size();
			blackList.addAll(newResult.getValue());
		}
		
		if (validSignatures < Common.REQUIRED_SET_FOR_QUORUM) {
			return null;
		}
		
		// Resolve & Write back
		Resolved 	resolved 	= ByzantineClientTools.resolver(rows, key, Common.NUM_OF_FIELDS);
		if (debug) {
			System.out.println("updatedReplicas:" + Arrays.toString(resolved.updatedReplicas.toArray()));
		}
		
		int		reqAnswers	= Common.REQUIRED_SET_FOR_QUORUM - resolved.updatedReplicas.size();	
		Status 	status 		= Status.OK;
		if (reqAnswers > 0) {
			String 		updatedNodes = ByzantineClientTools.getNodesIPs(resolved.updatedReplicas);
			String 		proxyInput 	 = ByzantineClientTools.buildWriteInjectedString(reqAnswers, updatedNodes, true);
			Insert 		stmt 		 = createWriteBackInsertStatment(table, key, resolved.mapping, proxyInput);
			InsertStmt 	insertStmt 	 = InsertStmt.createWriteBack(stmt, resolved.allSignatures,  resolved.mapping);
			
			status = insert(table, key, null, insertStmt);
		}
		
		if (status.equals(Status.OK)) {
			fillResult(resolved.mapping, results);
			return null;
		} else {
			return null;
		}
	}	

	private static class Results{
		public ResultSet rs;
		public InetAddress addr;
		
		public static Results createWithResults(ResultSet rs, InetAddress addr){
			Results res = new Results();
			res.rs = rs;
			res.addr = addr;
			return res;
		}
		
		public static Results createWithAddr(InetAddress addr){
			Results res = new Results();
			res.addr = addr;
			return res;
		}
	}
	
	// Returns ResultSet as is, on failure tries to get the failing host
	private Results execute(Session s, Statement stmt){
		ResultSet rs = null;
		try {
			rs = s.execute(stmt);
		} catch (WriteTimeoutException | ReadTimeoutException  e) {
			return Results.createWithAddr(e.getHost());
		} catch(Exception e) {
			if (debug)
				System.out.println("Exception is execute: " + e.getMessage());
			return null;
		}
		
		return Results.createWithResults(rs, rs.getExecutionInfo().getQueriedHost().getAddress());
	}
	
	// This function will try to try up to f+1 (proxy) nodes.
	// We call this function recursively till the blacklist is bigger than the number
	// of failures we permit. 
	@SuppressWarnings("unused")
	private Row coreReadAndValidate(
			Session sessionToUse,
			Statement stmt, 
			boolean shouldReadAll,
			String key,
			Set<Integer> fieldsNumbers,
			Set<InetAddress> blackList,
			String table,
			Set<String> fields,
			Map<String, ByteIterator> results,
			String readTS){
		
		Results excResults = execute(sessionToUse, stmt);
		if (excResults == null) return null;
		ResultSet rs = excResults.rs;
		
		Row row = null;
		if (rs != null && !rs.isExhausted()) {
			// Option 1
			if (!Common.isReadOption2) {
				row = handleResultReadOption1(rs, shouldReadAll, key, fieldsNumbers, readTS);
			// Option 2a
			} else if (Common.isReadOption2a){
				row = handleResultReadOption2a(rs, shouldReadAll, key, fieldsNumbers, table, readTS);
			// Option 2b
			} else {
				row = handleResultReadOption2b(rs, shouldReadAll, key, fieldsNumbers, table, results, readTS);
				if (row == null && !results.isEmpty()) {
					return null;
				}
			}
		}
	
		// It possible that we failed because it was a byzantine node
		// We try at least f+1 nodes.
		if (row == null && (blackList.size() < Common.F)) {		
			if (debug)
				System.out.println("Trying again with different node");
			
			blackList.add(excResults.addr);
			Session sessionTag = perNodeConnection.getRandomSession(blackList);
			return coreReadAndValidate(sessionTag, stmt, shouldReadAll, key, fieldsNumbers, blackList, table, fields, results, readTS);
		}
		
		return row;
	}
	
	private void fillResult(Row row, Map<String, ByteIterator> result){
		ColumnDefinitions cd = row.getColumnDefinitions();
		for (ColumnDefinitions.Definition def : cd) {
			if (!def.getName().startsWith(Common.VALUE_COLUMN_PREFIX)) {
				continue;
			}
			String name = def.getName().replace(Common.VALUE_COLUMN_PREFIX,
					"field");
			ByteBuffer val = row.getBytesUnsafe(def.getName());
			if (val != null) {
				result.put(name, new ByteArrayByteIterator(val.array()));
			} else {
				result.put(name, null);
			}
		}
	}
	
	// Translates our mapping to YCSB output.
	private void fillResult(Map<String, String> mapping, Map<String, ByteIterator> result){
		for (Map.Entry<String, String> entry : mapping.entrySet()) {
			if (!entry.getKey().startsWith(Common.VALUE_COLUMN_PREFIX)) {
				continue;
			}
			
			String name = entry.getKey().replace(Common.VALUE_COLUMN_PREFIX, "field");
			ByteBuffer val = ByteBuffer.wrap(entry.getValue().getBytes());
			if (val != null) {
				result.put(name, new ByteArrayByteIterator(val.array()));
			} else {
				result.put(name, null);
			}
		}
	}
	
	private static class InsertStmt{
		public Insert stmt;
		public String allSigns;
		public String symmetricSigns;
		
		public List<String> fields;
		public List<Object> values;
		
		public Long ts;
		
		public Map<String, String> resolvedMapping;
		public boolean isWriteBack = false;
		
		private InsertStmt(Insert stmt, String allSigns, Map<String, String> resolvedMapping) {
			this.stmt = stmt;
			this.allSigns = allSigns;
			this.resolvedMapping = resolvedMapping;
			isWriteBack = true;
		}
		
		public static InsertStmt createWriteBack(Insert stmt, String allSigns, Map<String, String> mapping) {
			return new InsertStmt(stmt, allSigns, mapping);
		}
		
		public InsertStmt(Insert stmt, String allSigns, List<String> fields, List<Object> values, Long ts, String symmetricSigns) {
			this.stmt = stmt;
			this.allSigns = allSigns;
			this.fields = fields;
			this.values = values;
			this.ts = ts;
			this.symmetricSigns = symmetricSigns;
		}
		

	}
	
	@SuppressWarnings("unused")
	private InsertStmt createInsertStatment(
			String table, 
			String key,
			Map<String, ByteIterator> values,
			String proxyInput) {

		
		Long 		 ts 	= ByzantineClientTools.getFreshTs();
		List<String> fields = new LinkedList<String>();
		List<String> vals   = new LinkedList<String>();
		
		TreeMap<String, ByteIterator> orderedMap 
						    = new TreeMap<String, ByteIterator>(values);
		
		Insert insertStmt = QueryBuilder.insertInto(table);

		// Add key
		insertStmt.value(Common.KEY_COLUMN, key);
		
		// Add fields
		String allSigns = "";
		
		String allVals;
		String allMetas;
		if (Common.isFullMACSignatures) {
			allVals = "";
			allMetas = "";
		}
		
		for (Map.Entry<String, ByteIterator> entry : orderedMap.entrySet()) {
			// Insert the value
			String value 		= entry.getValue().toString();
			String valNumber 	= entry.getKey().replaceAll("field", "");
			String valKey 		= Common.VALUE_COLUMN_PREFIX + valNumber;
			
			insertStmt	.value(valKey, value);
			fields		.add(valKey);
			vals		.add(value);

			// Compute value signature
			byte[] sign = ByzantineClientTools.computeStoreSignature(key, value, ts);
			if (sign == null) return null;
			String signS = new String(sign);
			allSigns += signS;

			// Insert the meta value <signature, ts, client_id>
			String metaVal = ByzantineClientTools.createMetaString(ts.toString(), Common.CLIENT_ID, signS);
			String metaKey = Common.META_COLUMN_PREFIX + valNumber;
			
			insertStmt	.value(metaKey, metaVal);
			fields		.add(metaKey);
			vals		.add(metaVal);
			
			if (Common.isFullMACSignatures) {
				allVals += value;
				allMetas += metaVal;
			}
		}
		
		String symmetricSigns = null;
		if (Common.isFullMACSignatures) {
			symmetricSigns = ByzantineClientTools.computeSymmetricSignature(key, allVals, allMetas, perNodeConnection.hosts);
			symmetricSigns += "#";
		}

		// Insert signatures column for replies in the read and for some commands in the write
		if (proxyInput == null) {
			proxyInput = "";
		}
		
		if (Common.isFullMACSignatures) {
			proxyInput = symmetricSigns + proxyInput;
		}
		
		// Add signatures column
		insertStmt.value(Common.NODES_SIGNATURES_COLUMN, proxyInput);

		insertStmt.setDefaultTimestamp(ts);
		insertStmt.setConsistencyLevel(writeConsistencyLevel);

		if (debug) {
			System.out.println("Created: " + insertStmt.toString());
		}
		
		return new InsertStmt(insertStmt, allSigns, fields, new ArrayList<Object>(vals), ts, symmetricSigns);
	}
	
	private Insert createInsertStatment(
			InsertStmt insertData,
			String table, 
			String key,
			String proxyInput) {
		
		Insert insertStmt = QueryBuilder.insertInto(table);

		// Add key
		insertStmt.value(Common.KEY_COLUMN, key);
		
		// Add values and meta values
		insertStmt.values(insertData.fields, insertData.values);

		// Insert signatures column for replies in the read and for some commands in the write
		if (proxyInput == null) {
			proxyInput = "";
		}
		
		if (Common.isFullMACSignatures && insertData.symmetricSigns != null) {
			proxyInput = insertData.symmetricSigns + proxyInput;
		}
		
		// Add signatures column
		insertStmt.value(Common.NODES_SIGNATURES_COLUMN, proxyInput);
		
		insertStmt.setDefaultTimestamp(insertData.ts);
		insertStmt.setConsistencyLevel(writeConsistencyLevel);

		if (debug) {
			System.out.println("Re Created: " + insertStmt.toString());
		}
		
		return insertStmt;
	}
	
	private Insert createWriteBackInsertStatment(
			String table, 
			String key,
			Map<String, String> values,
			String proxyInput) {
		
		Insert insertStmt = QueryBuilder.insertInto(table);

		// Add key
		insertStmt.value(Common.KEY_COLUMN, key);
		
		// Gets all values and meta values
		for (Map.Entry<String, String> entry : values.entrySet()) {
			insertStmt.value(entry.getKey(), entry.getValue());
		}

		// Insert signatures column for replies in the read and for some commands in the write
		if (proxyInput == null) {
			proxyInput = "";
		}
		
		insertStmt.value(Common.NODES_SIGNATURES_COLUMN, proxyInput);

		// Timestamp is injected later to cells on server side.
		//insertStmt.setDefaultTimestamp(ts);
		
		insertStmt.setConsistencyLevel(writeConsistencyLevel);

		if (debug) {
			System.out.println("Re Created: " + insertStmt.toString());
		}
		
		return insertStmt;
	}
	
	private static class InsertResult{
		public Status stat;
		public InetAddress proxyNode;
		public InsertStmt insertStmt;
		
		public InsertResult(Status stat, InetAddress proxyNode, InsertStmt insertStmt) {
			this.stat = stat;
			this.proxyNode = proxyNode;
			this.insertStmt = insertStmt;
		}
		
		public static InsertResult createErrorResult() {
			return new InsertResult(Status.ERROR, null, null);
		}
		
		public static InsertResult createErrorResult(ResultSet res, InsertStmt insertStmt) {
			return new InsertResult(Status.ERROR, res.getExecutionInfo().getQueriedHost().getAddress(), insertStmt);
		}
		
		public static InsertResult createErrorResult(InetAddress addr, InsertStmt insertStmt) {
			return new InsertResult(Status.ERROR, addr, insertStmt);
		}
	}
	
	private InsertResult coreInsertAndValidate(
			Session sessionToUse,
			String table, 
			String key,
			Map<String, ByteIterator> values,
			InsertStmt inputInsertStmt) {
		
		// Create or reuse insert statement
		InsertStmt insertStmt = null; 
		if (inputInsertStmt == null) {
			insertStmt = createInsertStatment(table, key, values, null);
		} else {
			insertStmt = inputInsertStmt;
			if (debug) 
				System.out.println("re using insert statement");
		}
		if (insertStmt == null) {
			return InsertResult.createErrorResult();
		}
		
		Results excResults = execute(sessionToUse, insertStmt.stmt);
		if (excResults == null){
			if (debug) 
				System.out.println("insert results is null");
			return InsertResult.createErrorResult();
		}
		
		if (readConsistencyLevel != ConsistencyLevel.QUORUM) {
			return new InsertResult(Status.OK, null, null);
		}
		
		ResultSet results = excResults.rs;
		if (results == null || results.isExhausted()){
			return InsertResult.createErrorResult(excResults.addr, insertStmt);
		}

		// list for fetching more ACKs from new nodes
		Set<String> interactedNodesList = null;
		if (Common.isInsertOption2) {
			interactedNodesList = new HashSet<String>();
		}
		
		int validStoreAcks =  ByzantineClientTools.validStoreAcks(
				 results, insertStmt.allSigns.getBytes(), interactedNodesList, Common.REQUIRED_SET_FOR_QUORUM);
		
		if (validStoreAcks >= Common.REQUIRED_SET_FOR_QUORUM) {
			if (debug) {
				System.out.println("Success");
			} 
			return new InsertResult(Status.OK, null, null);
		}
		
		if (debug) {
			System.out.println("failed, got only " + validStoreAcks);
		}
		
		if (!Common.isInsertOption2 ||
			validStoreAcks < Common.REQUIRED_SET_FOR_RETRY) {
			return InsertResult.createErrorResult(results, insertStmt);			
		}
			
		// Try to milk more
		String interactedNodesString = ByzantineClientTools.getNodesIPs(interactedNodesList);
		Session sameNodeSession 	 = perNodeConnection.getSession(excResults.addr);

		int newValidStoreAcks = 0;
		Set<String> newInteractedNodesList = null;
		int retryNum = 0;
		do {
			retryNum++;
			interactedNodesString = ByzantineClientTools.concatNodesIps(interactedNodesString, newInteractedNodesList);
			int newRequired 	  = Common.REQUIRED_SET_FOR_QUORUM - validStoreAcks;
			
			Insert newInsertStmnt = null;
			if (inputInsertStmt != null && inputInsertStmt.isWriteBack) {
				String proxyInput = ByzantineClientTools.buildWriteInjectedString(newRequired, interactedNodesString, true);
				newInsertStmnt 	  = createWriteBackInsertStatment(table, key, insertStmt.resolvedMapping, proxyInput);
			} else {
				String proxyInput = ByzantineClientTools.buildWriteInjectedString(newRequired, interactedNodesString, false);
				newInsertStmnt    = createInsertStatment(insertStmt, table, key, proxyInput);
			}
			
			Results newExcResults = execute(sameNodeSession, newInsertStmnt);
			if (newExcResults == null){
				if (debug) 
					System.out.println("insert new results is null");
				return InsertResult.createErrorResult();
			}
			
			ResultSet newResults = newExcResults.rs;
			if (newResults == null || newResults.isExhausted()){
				return InsertResult.createErrorResult(newExcResults.addr, insertStmt);
			}
			
			newInteractedNodesList = new HashSet<String>();
			newValidStoreAcks = ByzantineClientTools.validStoreAcks(
					newResults, insertStmt.allSigns.getBytes(), newInteractedNodesList, newRequired);
			
			validStoreAcks += newValidStoreAcks;
			if (validStoreAcks >= Common.REQUIRED_SET_FOR_QUORUM) {
				if (debug) {
					System.out.println("Success after retry");
				} 
				return new InsertResult(Status.OK, null, null);
			}
			
			if (debug) {
				System.out.println("goodSignatures " + validStoreAcks);
				System.out.println("requiredAnswers " + Common.REQUIRED_SET_FOR_QUORUM);
			}
		} while (newInteractedNodesList.size() > 0 && retryNum < Common.F);

		return InsertResult.createErrorResult(results, insertStmt);
	}

	// insertStmt is used for the write back
	private Status insert(
			String table, 
			String key,
			HashMap<String, ByteIterator> values,
			InsertStmt insertStmt) {

		InsertResult res = coreInsertAndValidate(session, table, key, values, insertStmt);
		if (res.stat == Status.OK) {
			return res.stat;
		}
		
		if (res.proxyNode == null){
			if (debug)
				System.out.println("res.proxyNode is null");
			return res.stat;
		}
		
		// It possible that we failed because it was a Byzantine node
		// We try at least f+1 nodes.
		// In the f round of this loop, the blacklist size will have f blacklisted nodes (at least)
		Set<InetAddress> blackList = new HashSet<InetAddress>();
		while (blackList.size() < Common.F) {
			if (debug)
				System.out.println("Trying again with different node");
			
			blackList.add(res.proxyNode);
			Session sessionTag = perNodeConnection.getRandomSession(blackList);
			res = coreInsertAndValidate(sessionTag, table, key, values, res.insertStmt);
			if (res.stat == Status.OK) {
				return res.stat;
			}
			
			if (res.proxyNode == null){
				if (debug)
					System.out.println("res.proxyNode is null");
				return res.stat;
			}
		}
		
		return Status.ERROR;
	}
	
	@SuppressWarnings("unused")
	public Status read(
			String table, 
			String key, 
			Set<String> fields,
			HashMap<String, ByteIterator> result) {
		try {
			// Read all if requested or it is Read option 2b (client resolves)
			boolean shouldReadAll = 
					(fields == null) ||
					(Common.isReadOption2 && 
					 !Common.isReadOption2a);

			// Translates the set of strings "field[i]" to set of integers [i]
			Set<Integer> fieldsNumbers = null;
			if (!shouldReadAll) {
				fieldsNumbers = getFieldsNumbers(fields);
			}

			// Prepare our extra data we send to the server
			Long ts = ByzantineClientTools.getFreshTs();
			String readTS = ts.toString();
			String injectedKey = ByzantineClientTools.injectKeyData(key, ts.toString(), Common.CLIENT_ID, null, shouldReadAll, fieldsNumbers);
			
			// Create the read statement
			Statement stmt = createReadStatment(table, injectedKey,	fieldsNumbers, shouldReadAll);
			if (debug) {
				System.out.println(stmt.toString());
			}

			// Create a blacklist that might be used on failure. 
			Set<InetAddress> blacklist = new HashSet<InetAddress>();
			Row row = coreReadAndValidate(session, stmt, shouldReadAll, key, fieldsNumbers, blacklist, table, fields, result, readTS);
			if (row == null && result.isEmpty()) {
				return Status.ERROR;
			}
			
			// Parse answer if not done yet (if we resolve the answer, we don't create a row for that)
			if (result.isEmpty()) {
				fillResult(row, result);
			}

			return Status.OK;

		} catch (Exception e) {
			e.printStackTrace();
			System.out.println("Error reading key: " + key);
			return Status.ERROR;
		}
	}
	
	public Status insert(
			String table, 
			String key,
			HashMap<String, ByteIterator> values) {
		return insert(table, key, values, null);
	}
}
