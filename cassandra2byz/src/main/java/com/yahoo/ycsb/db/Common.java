package com.yahoo.ycsb.db;

public class Common {
	public static final String KEY_COLUMN   			= "key_1";
	public static final String VALUE_COLUMN_PREFIX 		= "val_";
	public static final String META_COLUMN_PREFIX  		= "meta_";
	public static final String NODES_SIGNATURES_COLUMN 	= "signatures";
	public static final String CLIENT_ID 				= "clien1";
	public static final String KEYSPACE  				= "demo";
	public static final String TABLE 	 				= "tbl7";
	
	public static final String TABLE_FULL_NAME = 
			String.format("%s.%s", KEYSPACE,TABLE);
	
	// Key-Value scheme
//	public static final String VALUE_COLUMN = "val1";
//	public static final String META_COLUMN  = "meta1";
	
	public static final String EMPTY_MESSAGE = "E";
	public static final String WRITE_BACK_MESSAGE = "WB";
	public static final String RESOLVED_PREFIX = "R#";
	public static final String REQUEST_ALL_FIELDS = "*";
	
	public static final boolean isMACSignatures = true;
	public static final boolean isFullMACSignatures = true;
	
	public static final boolean isReadOption2 = true;
	public static final boolean isReadOption2a = false;
	
	public static final boolean isInsertOption2 = true;
	
	public static final int F = 1;
	
	// Config for simple QUORUM 
//	public static final int REQUIRED_SET_FOR_QUORUM = F + 1;
//	public static final int REQUIRED_SET_FOR_RETRY = 1;
	
	// Config for Byzantine QUORUM 
	public static final int REQUIRED_SET_FOR_QUORUM = (2*F) + 1;
	public static final int REQUIRED_SET_FOR_RETRY = F + 1;
	
	public static final int NUM_OF_FIELDS = 3;
}
