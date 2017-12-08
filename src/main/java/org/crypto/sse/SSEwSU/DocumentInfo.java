package org.crypto.sse.SSEwSU;

class DocumentInfo {
	byte[] documentID;
	byte[] Kd1;
	byte[] Kd2;
	byte[] encKey;
	byte[] encryptedMetadata;
	byte[] Kd2Enc;
	byte[] KdEdit;

	DocumentInfo(byte[] docID, byte[] kd1, byte[] kd2, byte[] encKey, byte[] encryptedMetadata, byte[] kd2Enc) {
		this.documentID = docID;
		this.Kd1 = kd1;
		this.Kd2 = kd2;
		this.Kd2Enc = kd2Enc;
		this.encKey = encKey;
		this.encryptedMetadata = encryptedMetadata;
	}
	DocumentInfo(byte[] docID, byte[] kd1, byte[] kd2, byte[] encKey, byte[] encryptedMetadata, byte[] kd2Enc, byte[] KdEdit) {
		this(docID, kd1, kd2, encKey, encryptedMetadata, kd2Enc);
		this.KdEdit = KdEdit;
	}
}