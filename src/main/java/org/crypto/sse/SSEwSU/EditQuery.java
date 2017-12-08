package org.crypto.sse.SSEwSU;

import java.io.Serializable;

class EditQuery<CT extends Serializable> implements Serializable {
	private static final long serialVersionUID = 6418008390394745334L;
	byte[] authTokenID;
	CT queryCiphertext;
	byte[] encryptedMetadata;

	EditQuery(byte[] tokID, CT ct, byte[] encryptedMetadata) {
		this.authTokenID = tokID;
		this.queryCiphertext = ct;
		this.encryptedMetadata = encryptedMetadata;
	}
}