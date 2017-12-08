package org.crypto.sse.SSEwSU;

import java.io.Serializable;

class ServerResponse implements Serializable {
	private static final long serialVersionUID = -5797489427757450005L;
	byte[] authTokenID;
	byte[] yCT;
	
	ServerResponse(byte[] a, byte[] b) {
		authTokenID = a;
		yCT = b;
	}
}