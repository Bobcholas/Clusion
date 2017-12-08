package org.crypto.sse.SSEwSU;

import java.io.Serializable;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.commons.lang.SerializationUtils;
import org.crypto.sse.CryptoPrimitives.RewritableDeterministicHash;

class LocalServer<CT_G extends Serializable, RDH extends RewritableDeterministicHash<CT_G>> implements Server<CT_G, RDH> {

	// map: EncryptedDocumentWordPair -> EncryptedDocumentMetadata
	Map<CT_G, byte[]> encryptedMM;
	// map: authTokenID -> authToken
	Map<ByteBuffer, byte[]> authTokenMap;
	Map<ByteBuffer, byte[]> authTokenEditMap;
	final boolean editPerms;
	private SSEwSUSettings<CT_G, RDH> settings;

	LocalServer(SSEwSUSettings<CT_G, RDH> settings, boolean editPerms) {
		this.settings = settings;
		this.editPerms = editPerms;
	}
	LocalServer(SSEwSUSettings<CT_G, RDH> settings) {
		this(settings, false);
	}
	
	@Override
	public void setup(Map<CT_G, byte[]> encryptedMM) {
		this.encryptedMM = encryptedMM;
		this.authTokenMap = new HashMap<ByteBuffer, byte[]>();
		if (editPerms){
			this.authTokenEditMap = new HashMap<ByteBuffer, byte[]>();
		}
	}

	@Override
	public Set<ServerResponse> search(Set<byte[]> queryCiphertexts) {			
		Set<ServerResponse> resultSet = new HashSet<ServerResponse>();
		for (byte[] qCT : queryCiphertexts) {
			@SuppressWarnings("unchecked")
			Query<CT_G> query = (Query<CT_G>) SerializationUtils.deserialize(qCT);
			byte[] authToken = authTokenMap.get(ByteBuffer.wrap(query.authTokenID));
			if (authToken == null) {
				continue;
			}

			CT_G xCT = settings.getRDH().Apply(query.queryCiphertext, authToken);
			byte[] yCT = encryptedMM.get(xCT);
			if (yCT != null)
				resultSet.add(new ServerResponse(query.authTokenID, yCT));
		}
		return resultSet;
	}

	@Override
	public void giveAccess(byte[] authTokID, byte[] authTok) {
		authTokenMap.put(ByteBuffer.wrap(authTokID), authTok);
	}
	
	@Override
	public void removeAccess(byte[] authTokID) {
		authTokenMap.remove(ByteBuffer.wrap(authTokID));
	}
	
	@Override
	public void giveEditAccess(byte[] authTokID, byte[] authTok) {
		if (!editPerms){
			throw new IllegalStateException("Edit permissions not enabled");
		}
		authTokenEditMap.put(ByteBuffer.wrap(authTokID), authTok);	
	}
	
	@Override
	public void removeEditAccess(byte[] authTokID) {
		if (!editPerms){
			throw new IllegalStateException("Edit permissions not enabled");
		}
		authTokenEditMap.remove(ByteBuffer.wrap(authTokID));			
	}
	
	@Override
	public void addKeyword(EditQuery<CT_G> query) {
		//TODO: Where does metadata come from? Presumably needs to be recalculated...
		byte[] authTokenEdit = authTokenEditMap.get(ByteBuffer.wrap(query.authTokenID));
		if (authTokenEdit == null){ //not authorized
			return;
		}
		CT_G newKeywordToken = settings.getRDH().Apply(query.queryCiphertext, authTokenEdit);
		encryptedMM.put(newKeywordToken, query.encryptedMetadata);
	}
	
	@Override
	public void removeKeyword(EditQuery<CT_G> query) {
		byte[] authTokenEdit = authTokenEditMap.get(ByteBuffer.wrap(query.authTokenID));
		if (authTokenEdit == null){ //not authorized
			return;
		}
		CT_G newKeywordToken = settings.getRDH().Apply(query.queryCiphertext, authTokenEdit);
		encryptedMM.remove(newKeywordToken);			
	}
	
	@Override
	public SSEwSUSettings<CT_G, RDH> getSettings() {
		return settings;
	}

}