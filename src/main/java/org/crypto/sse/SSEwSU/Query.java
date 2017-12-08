package org.crypto.sse.SSEwSU;

import java.io.Serializable;

class Query<CT extends Serializable> implements Serializable {
	private static final long serialVersionUID = -1891843663804523275L;
	byte[] authTokenID;
	CT queryCiphertext;

	Query(byte[] tokID, CT ct) {
		this.authTokenID = tokID;
		this.queryCiphertext = ct;
	}
}