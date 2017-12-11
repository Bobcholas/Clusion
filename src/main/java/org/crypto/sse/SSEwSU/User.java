package org.crypto.sse.SSEwSU;

import java.io.IOException;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.crypto.NoSuchPaddingException;

import org.apache.commons.lang.SerializationUtils;
import org.crypto.sse.CryptoPrimitives.RewritableDeterministicHash;

import com.javamex.classmexer.MemoryUtil;

class User<CT_G extends Serializable, RDH extends RewritableDeterministicHash<CT_G>> {

	public final static double nano = 1000000000.0;
	
	@SuppressWarnings("unused")
	private String username;
	byte[][] userKeys;
	List<DocumentInfo> accessList;
	private Server<CT_G, RDH> server;
	private SSEwSUSettings<CT_G, RDH> settings;

	public User(String username, byte[][] keys, Server<CT_G, RDH> server) {
		this.username = username;
		this.userKeys = keys;
		this.accessList = new ArrayList<DocumentInfo>();
		this.server = server;
		this.settings = server.getSettings();
	}

	public Collection<String> search(String keyword) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException {
		long startTime = System.nanoTime();
		
		Set<byte[]> queryCiphertexts = new HashSet<>();
		Map<ByteBuffer, byte[]> authTokenIDToEncryptionKey = new HashMap<>();
		for (DocumentInfo document : this.accessList) {
			// compute auth token
			byte[] authTokenID = settings.F(userKeys[1], document.documentID);
			// compute query ciphertext
			CT_G queryCT = settings.getRDH().H(settings.F(document.Kd1, settings.wordToID(keyword)), settings.F(userKeys[0], document.documentID));
			queryCiphertexts.add(SerializationUtils.serialize(new Query<CT_G>(authTokenID, queryCT)));
			authTokenIDToEncryptionKey.put(ByteBuffer.wrap(authTokenID), document.encKey);
		}

		long timeSpentCalculatingMemory = 0;
		long serverStartTime = System.nanoTime();
		if (settings.isDebug())
			System.out.printf("Search query    bandwidth [user -> server]: %d B\n", 
				MemoryUtil.deepMemoryUsageOf(queryCiphertexts));
		timeSpentCalculatingMemory += ((System.nanoTime() - serverStartTime) / nano);
		
		// send query ciphertext to server
		Set<ServerResponse> queryResponse = this.server.search(queryCiphertexts);
		// done with server search
		
		long calcStartTime = System.nanoTime();
		if (settings.isDebug())
			System.out.printf("Search response bandwidth [user <- server]: %d B\n", 
				MemoryUtil.deepMemoryUsageOf(queryResponse) );
		timeSpentCalculatingMemory += ((System.nanoTime() - calcStartTime) / nano);
		double serverElapsed = ((System.nanoTime() - serverStartTime) / nano);
		if (settings.isDebug())
			System.out.printf("Server search time: %.2fms\n", 1000 * (serverElapsed - timeSpentCalculatingMemory));
		
		// decrypt response from server
		Collection<String> result = new HashSet<String>(queryResponse.size());
		for (ServerResponse encryptedResponse : queryResponse) {
			String metadata = settings.Decrypt(authTokenIDToEncryptionKey.get(ByteBuffer.wrap(encryptedResponse.authTokenID)), encryptedResponse.yCT);
			result.add(metadata.trim());
		}
		
		double elapsed = ((System.nanoTime() - startTime) / nano);
		if (settings.isDebug())
			System.out.printf("User search time: %.2fms\n", 1000 * (elapsed - serverElapsed - timeSpentCalculatingMemory));
		return result;
	}
	
	private CT_G makeEditCiphertext(DocumentInfo document, String keyword) throws NoSuchAlgorithmException, UnsupportedEncodingException{
		CT_G editCT = settings.getRDH().H(settings.F(document.Kd1, settings.wordToID(keyword)), settings.F(document.KdEdit, userKeys[0]));
		return editCT;
	}
	
	public void addKeyword(DocumentInfo document, String keyword) throws NoSuchAlgorithmException, UnsupportedEncodingException{
		CT_G editCT = makeEditCiphertext(document, keyword);
		EditQuery<CT_G> editQuery = new EditQuery<CT_G>(settings.F(userKeys[1], document.KdEdit), editCT, document.encryptedMetadata);
		server.addKeyword(editQuery);
	}
	
	public void removeKeyword(DocumentInfo document, String keyword) throws NoSuchAlgorithmException, UnsupportedEncodingException{
		CT_G editCT = makeEditCiphertext(document, keyword);
		EditQuery<CT_G> editQuery = new EditQuery<CT_G>(settings.F(userKeys[1], document.KdEdit), editCT, null);
		server.removeKeyword(editQuery);
	}

	public void addDocumentInfo(byte[] docID, byte[] docKey, byte[] encKey) {
		this.accessList.add(new DocumentInfo(docID, docKey, null, encKey, null, null));
	}
	
	public void addDocumentInfo(byte[] docID, byte[] docKey, byte[] encKey, byte[] kdEdit) {
		this.accessList.add(new DocumentInfo(docID, docKey, null, encKey, null, null, kdEdit));
	}

}