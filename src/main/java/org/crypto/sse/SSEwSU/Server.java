package org.crypto.sse.SSEwSU;

import java.io.Serializable;
import java.util.Map;
import java.util.Set;

import org.crypto.sse.CryptoPrimitives.RewritableDeterministicHash;

interface Server<CT_G extends Serializable, RDH extends RewritableDeterministicHash<CT_G>> {

	void setup(Map<CT_G, byte[]> encryptedMM);

	Set<ServerResponse> search(Set<byte[]> queryCiphertexts);

	void giveAccess(byte[] authTokID, byte[] authTok);

	void removeAccess(byte[] authTokID);

	void giveEditAccess(byte[] authTokID, byte[] authTok);

	void removeEditAccess(byte[] authTokID);

	void addKeyword(EditQuery<CT_G> query);

	void removeKeyword(EditQuery<CT_G> query);
	
	SSEwSUSettings<CT_G, RDH> getSettings();

}