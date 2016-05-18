package com.yahoo.ycsb.db;

import java.util.HashMap;
import java.util.Map;

// This map should be constructed dynamically. We use it this way to show
// a simulation of the run and measure the performance
public class IpNodeBinding {
	final static public Map<String, String> ipToNodeId = 
			new HashMap<String, String>() {{
				put("127.0.0.1","node1");
				put("127.0.0.2","node2");
				put("127.0.0.3","node3");
				put("127.0.0.4","node4");
		}};

}
