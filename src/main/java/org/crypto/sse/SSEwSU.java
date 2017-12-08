/** * Copyright (C) 2017 Nick Cunningham and Sorin Vatasoiu
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.crypto.sse;

import java.io.IOException;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.regex.Pattern;

import javax.crypto.NoSuchPaddingException;

import org.apache.commons.lang.SerializationUtils;
import org.crypto.sse.CryptoPrimitives.RewritableDeterministicHash;

import com.google.common.collect.Multimap;
import com.javamex.classmexer.MemoryUtil;

public class SSEwSU<CT_G extends Serializable, RDH extends RewritableDeterministicHash<CT_G>> {

	public final static String START_STRING = "STARTSTRING";
	public final static int idLengthBytes = 128 / 8;
	public final static double nano = 1000000000.0;
	public final static int AES_IV_LENGTH = 16;
	public final static int METADATA_LENGTH = 256;
	private final static boolean debug = true;

	public final int securityParameter;
	public final RDH rdh;
	
	private Server server;
	private Manager manager;

	public SSEwSU(Multimap<String, String> mm, RDH rdh, int securityParameter) 
			throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException, InterruptedException, ExecutionException {
		
		this.securityParameter = securityParameter;
		this.rdh = rdh;

		this.server = new Server();
		this.manager = new Manager();
		
		long startTime = System.nanoTime();
		this.manager.setup(this.server, mm);
		double elapsed = ((System.nanoTime() - startTime) / nano);
		debugPrintf("Setup took %.2fms\n", 1000 * elapsed);
		debugPrintf("%d document word pairs inserted [%.4fms/pair]\n%d total documents\n", 
				this.server.encryptedMM.size(), 
				1000 * elapsed / this.server.encryptedMM.size(),
				this.manager.documents.size());
		
		if (debug) {
			long serverSizeMB = MemoryUtil.deepMemoryUsageOf(this.server) / 1024 / 1024;
			debugPrintf("SERVER SIZE: %d MB\n", serverSizeMB);
			debugPrintf("SERVER UPLOAD TIME: %.2fms\n", 1000 * elapsed);
		}
	}

	public void enroll(String username) throws UserAlreadyExists {
		this.manager.enroll(username);
	}

	public Collection<String> shareDoc(String documentName, String username) throws UserDoesntExist, DocumentDoesntExist, UnsupportedEncodingException {
		Collection<String> sharedDocs = new HashSet<String>();
		if (documentName.contains("*")) {
			Pattern p = Pattern.compile(documentName);
			for (String name : this.manager.documents.keySet()) {
				if (p.matcher(name).matches()) {
					this.manager.shareDoc(name, username);
					sharedDocs.add(name);
				}
			}
		} else {
			this.manager.shareDoc(documentName, username);
			sharedDocs.add(documentName);
		}
		return sharedDocs;
	}

	public Collection<String> unshareDoc(String documentName, String username) throws UserDoesntExist, DocumentDoesntExist, UnsupportedEncodingException {
		Collection<String> unsharedDocs = new HashSet<String>();
		if (documentName.contains("*")) {
			Pattern p = Pattern.compile(documentName);
			for (String name : this.manager.documents.keySet()) {
				if (p.matcher(name).matches()) {
					this.manager.unshareDoc(name, username);
					unsharedDocs.add(name);
				}
			}
		} else {
			this.manager.unshareDoc(documentName, username);
			unsharedDocs.add(documentName);
		}
		return unsharedDocs;
	}

	public Collection<String> query(String username, String keyword) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException {
		if (!this.manager.users.containsKey(username)) {
			System.out.println("User " + username + " does not exist");
			return null;
		}
		debugPrintf("User %s has access to %d files\n", username, 
				this.manager.users.get(username).accessList.size());
		return this.manager.users.get(username).search(keyword);
	}
	
	public Boolean addKeyword(String username, String keyword, String documentName){
		if (!this.manager.users.containsKey(username)) {
			System.out.println("User " + username + " does not exist");
			return null;
		}
		User u = this.manager.users.get(username);
		DocumentInfo d = this.manager.documents.get(documentName);
		if (d == null){
			System.out.println("Document " + documentName + " does not exist");
			return null;
		}
		try{
			u.addKeyword(d, keyword);
		}catch (Exception e){
			e.printStackTrace();
			return false;
		}
		return true;
	}
	public Boolean removeKeyword(String username, String keyword, String documentName){
		if (!this.manager.users.containsKey(username)) {
			System.out.println("User " + username + " does not exist");
			return null;
		}
		User u = this.manager.users.get(username);
		DocumentInfo d = this.manager.documents.get(documentName);
		if (d == null){
			System.out.println("Document " + documentName + " does not exist");
			return null;
		}
		try{
			u.removeKeyword(d, keyword);
		}catch (Exception e){
			e.printStackTrace();
			return false;
		}
		return true;
	}

	/**
	 * Wrapper to calculate HMAC with results taken from integers mod p, for prime p which is also the order of the RDH
	 * @param key Key for the HMAC
	 * @param x Message to calculate for
	 * @return The result, on the interval [0, p).
	 */
	public byte[] F(byte[] key, byte[] x) throws UnsupportedEncodingException { 
		// must be in F_p for prime p
		BigInteger tmp = new BigInteger(CryptoPrimitives.generateHmac(key, x));
		return tmp.mod(rdh.getFieldOrder()).toByteArray(); 
	}

	/**
	 * Wrapper to calculate an HMAC (keyed pseudorandom function)
	 * @param key Key of HMAC
	 * @param x Message to calculate for
	 * @return The HMAC output
	 */
	public byte[] G(byte[] key, byte[] x) throws UnsupportedEncodingException { 
		//note: security parameter here is just parameter of HMAC
		return CryptoPrimitives.generateHmac(key, x);
	}

	public byte[] Encrypt(byte[] key, String plaintext) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException { 
		return CryptoPrimitives.encryptAES_CTR_String(key, CryptoPrimitives.randomBytes(AES_IV_LENGTH), plaintext, METADATA_LENGTH);
	}

	public String Decrypt(byte[] key, byte[] ciphertext) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException { 
		return new String(CryptoPrimitives.decryptAES_CTR_String(ciphertext, key)); 
	}

	static class Query<CT> implements Serializable {
		private static final long serialVersionUID = -1891843663804523275L;
		private byte[] authTokenID;
		private CT queryCiphertext;

		Query(byte[] tokID, CT ct) {
			this.authTokenID = tokID;
			this.queryCiphertext = ct;
		}
	}
	
	static class EditQuery<CT> implements Serializable {
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
	
	static class ServerResponse {
		byte[] authTokenID;
		byte[] yCT;
		
		ServerResponse(byte[] a, byte[] b) {
			authTokenID = a;
			yCT = b;
		}
	}

	class Server {

		// map: EncryptedDocumentWordPair -> EncryptedDocumentMetadata
		Map<CT_G, byte[]> encryptedMM;
		// map: authTokenID -> authToken
		Map<ByteBuffer, byte[]> authTokenMap;
		Map<ByteBuffer, byte[]> authTokenEditMap;
		final boolean editPerms;

		Server(boolean editPerms) {
			this.editPerms = editPerms;
		}
		Server() {
			this(false);
		}
		
		public void setup(Map<CT_G, byte[]> encryptedMM) {
			this.encryptedMM = encryptedMM;
			this.authTokenMap = new HashMap<ByteBuffer, byte[]>();
			if (editPerms){
				this.authTokenEditMap = new HashMap<ByteBuffer, byte[]>();
			}
		}

		public Set<ServerResponse> search(Set<byte[]> queryCiphertexts) {			
			Set<ServerResponse> resultSet = new HashSet<ServerResponse>();
			for (byte[] qCT : queryCiphertexts) {
				Query<CT_G> query = (SSEwSU.Query<CT_G>) SerializationUtils.deserialize(qCT);
				byte[] authToken = authTokenMap.get(ByteBuffer.wrap(query.authTokenID));
				if (authToken == null) {
					continue;
				}

				CT_G xCT = rdh.Apply(query.queryCiphertext, authToken);
				byte[] yCT = encryptedMM.get(xCT);
				if (yCT != null)
					resultSet.add(new ServerResponse(query.authTokenID, yCT));
			}
			return resultSet;
		}

		public void giveAccess(byte[] authTokID, byte[] authTok) {
			authTokenMap.put(ByteBuffer.wrap(authTokID), authTok);
		}
		public void removeAccess(byte[] authTokID) {
			authTokenMap.remove(ByteBuffer.wrap(authTokID));
		}
		public void giveEditAccess(byte[] authTokID, byte[] authTok) {
			if (!editPerms){
				throw new IllegalStateException("Edit permissions not enabled");
			}
			authTokenEditMap.put(ByteBuffer.wrap(authTokID), authTok);	
		}
		public void removeEditAccess(byte[] authTokID) {
			if (!editPerms){
				throw new IllegalStateException("Edit permissions not enabled");
			}
			authTokenEditMap.remove(ByteBuffer.wrap(authTokID));			
		}
		public void addKeyword(EditQuery<CT_G> query) {
			//TODO: Where does metadata come from? Presumably needs to be recalculated...
			byte[] authTokenEdit = authTokenEditMap.get(ByteBuffer.wrap(query.authTokenID));
			if (authTokenEdit == null){ //not authorized
				return;
			}
			CT_G newKeywordToken = rdh.Apply(query.queryCiphertext, authTokenEdit);
			encryptedMM.put(newKeywordToken, query.encryptedMetadata);
		}
		public void removeKeyword(EditQuery<CT_G> query) {
			byte[] authTokenEdit = authTokenEditMap.get(ByteBuffer.wrap(query.authTokenID));
			if (authTokenEdit == null){ //not authorized
				return;
			}
			CT_G newKeywordToken = rdh.Apply(query.queryCiphertext, authTokenEdit);
			encryptedMM.remove(newKeywordToken);			
		}

	}
	
	class Manager {

		Map<String, User> users;
		private Map<String, DocumentInfo> documents;
		private byte[][] masterKeys;
		private Server server;
		private final boolean editPerms;

		Manager(boolean edit) {
			this.editPerms = edit;
			users = new HashMap<String, User>();
			documents = new HashMap<String, DocumentInfo>();
			//masterKeys: mk[0] for kd, mk[1] ~kd (kd2), mk[2] used for enc, mk[3] optionally used for edit rights
			if (!edit){
				masterKeys = new byte[3][];
			}else{
				masterKeys = new byte[4][];
			}
		}
		Manager() { //default to no edit
			this(false);
		}
		
		public void setup(Server server, final Multimap<String, String> mm) 
				throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, 
				NoSuchProviderException, NoSuchPaddingException, IOException, InterruptedException, ExecutionException {
			
			this.server = server;
			
			// select master keys (3, or 4 if editing)
			for (int i = 0; i < masterKeys.length; ++i)
				masterKeys[i] = CryptoPrimitives.randomBytes(securityParameter);
			
			for (String documentName : mm.keySet()) {
				byte[] docID = documentNameToID(documentName);
				byte[] kd2 = F(masterKeys[1], docID);
				byte[] encKey = G(masterKeys[2], docID);
				DocumentInfo document;
				if (editPerms) {
					byte[] kdEdit = F(masterKeys[3], docID);
					document = 
							new DocumentInfo(docID,
									F(masterKeys[0], docID),
									kd2,
									encKey,
									Encrypt(encKey, documentName),
									F(kd2, docID),
									kdEdit);
				}else{
					document = 
							new DocumentInfo(docID,
									F(masterKeys[0], docID),
									kd2,
									encKey,
									Encrypt(encKey, documentName),
									F(kd2, docID));
				}
				
				documents.put(documentName, document);
			}

			List<Entry<String,String>> listOfDocWordPairs = new ArrayList<>(mm.entries());
			int totalWork = listOfDocWordPairs.size();
			int numThreads = Math.max(1, Math.min(totalWork, Runtime.getRuntime().availableProcessors()));
			int workPerThread = totalWork / numThreads;
			
			ExecutorService service = Executors.newFixedThreadPool(numThreads);
			List<Collection<Entry<String,String>>> inputs = new ArrayList<>(numThreads);
			
			for (int i = 0; i < numThreads; i++) {
				Collection<Entry<String,String>> tmp;
				if (i == numThreads - 1) {
					tmp = listOfDocWordPairs.subList(workPerThread * i, listOfDocWordPairs.size());
				} else {
					tmp = listOfDocWordPairs.subList(workPerThread * i, workPerThread * (i + 1));
				}
				inputs.add(i, tmp);
				debugPrintf("Thread #" + (i + 1) + " gets " + tmp.size() + " pairs\n");
			}

			debugPrintf("End of Partitioning\n");

			Map<CT_G, byte[]> encryptedMM = new HashMap<CT_G, byte[]>();
			List<Future<Map<CT_G, byte[]>>> futures = new ArrayList<>();
			for (final Collection<Entry<String,String>> input : inputs) {
				Callable<Map<CT_G, byte[]>> callable = 
						new Callable<Map<CT_G, byte[]>>() {
					
					public Map<CT_G, byte[]> call() throws Exception {
						return encryptDocWords(input);
					}
					
				};
				futures.add(service.submit(callable));
			}

			service.shutdown();

			for (Future<Map<CT_G, byte[]>> future : futures) {
				encryptedMM.putAll(future.get());
			}
			
			// send encrypted map to server
			this.server.setup(encryptedMM);
			

			if (debug) {
				long serverSize = MemoryUtil.deepMemoryUsageOf(encryptedMM) / 1024;
				debugPrintf("Server upload bandwidth: %d kB\n", serverSize);
			}
		}
		
		public Map<CT_G, byte[]> encryptDocWords(final Collection<Entry<String,String>> documentWordPairs) 
				throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException {
			
			// Build encrypted map from corpus of documents
			int i = 0;
			Map<CT_G, byte[]> encryptedMM = new HashMap<CT_G, byte[]>();
			for (Entry<String,String> docWord : documentWordPairs) {
				String documentName = docWord.getKey();
				String word = docWord.getValue();
				DocumentInfo document = documents.get(documentName);
			
				CT_G xCT = rdh.H(document.Kd2Enc, F(document.Kd1, wordToID(word)));
				encryptedMM.put(xCT, document.encryptedMetadata);
				
				if ((i++ % 2500) == 0) {
					debugPrintf("Thread %d is %.2f%% done [%d/%d]\n",
							Thread.currentThread().getId(), 
							(double) (100.0 * (double)i)/documentWordPairs.size(),
							i, documentWordPairs.size()); 
				}
			}
			return encryptedMM;
		}

		public User enroll(String username) throws UserAlreadyExists {
			if (users.containsKey(username)) {
				throw new UserAlreadyExists(username);
			}

			// generate keys for user
			User newUser = new User(username, new byte[][] {
				CryptoPrimitives.randomBytesBuffered(securityParameter),
				CryptoPrimitives.randomBytesBuffered(securityParameter)
			}, this.server);
			users.put(username, newUser);
			return newUser;
		}

		public void shareDoc(String documentName, String username, boolean allowEdit) throws UserDoesntExist, DocumentDoesntExist, UnsupportedEncodingException {
			if (!users.containsKey(username)) 
				throw new UserDoesntExist(username);

			if (!documents.containsKey(documentName))
				throw new DocumentDoesntExist(documentName);
			
			if (allowEdit && !this.editPerms){
				throw new IllegalStateException("Edit permissions not enabled");
			}

			User user = users.get(username);
			DocumentInfo document = documents.get(documentName);

			// compute authorization token
			byte[] authToken = rdh.GenToken(F(document.Kd2, document.documentID), F(user.userKeys[0], document.documentID));
			// compute authorization token id
			byte[] authTokenID = F(user.userKeys[1], document.documentID);

			if (allowEdit){
				byte[] authTokenEdit = rdh.GenToken(F(document.Kd2, document.documentID), F(user.userKeys[0], document.KdEdit));
				// compute authorization token id
				byte[] authTokenIDEdit = F(user.userKeys[1], document.KdEdit);
				this.server.giveEditAccess(authTokenIDEdit, authTokenEdit);
			}
			
			// send (token id, token) to server
			this.server.giveAccess(authTokenID, authToken);

			// send documentID, Kd, and Kd^enc to user
			if (!allowEdit){
				user.addDocumentInfo(document.documentID, document.Kd1, document.encKey);
			}else{
				user.addDocumentInfo(document.documentID, document.Kd1, document.encKey, document.KdEdit);
			}
		}
		//no edit if unspecified
		public void shareDoc(String documentName, String username) throws UserDoesntExist, DocumentDoesntExist, UnsupportedEncodingException {
			shareDoc(documentName, username, false);
		}

		public void unshareDoc(String documentName, String username) throws UserDoesntExist, DocumentDoesntExist, UnsupportedEncodingException {
			if (!users.containsKey(username)) 
				throw new UserDoesntExist(username);

			if (!documents.containsKey(documentName))
				throw new DocumentDoesntExist(documentName);

			User user = users.get(username);
			DocumentInfo document = documents.get(documentName);

			byte[] authTokenID = F(user.userKeys[1], document.documentID);
			this.server.removeAccess(authTokenID);
			
			if (this.editPerms){
				byte[] authTokenIDEdit = F(user.userKeys[1], document.KdEdit);
				this.server.removeEditAccess(authTokenIDEdit);
			}
		}

	}

	class User {

		@SuppressWarnings("unused")
		private String username;
		private byte[][] userKeys;
		private List<DocumentInfo> accessList;
		private Server server;
		private final boolean editPerms;

		public User(String username, byte[][] keys, Server server, boolean editPerms) {
			this.username = username;
			this.userKeys = keys;
			this.accessList = new ArrayList<DocumentInfo>();
			this.server = server;
			this.editPerms = editPerms;
		}
		public User(String username, byte[][] keys, Server server) {
			this(username, keys, server, false);
		}

		public Collection<String> search(String keyword) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException {
			long startTime = System.nanoTime();
			
			Set<byte[]> queryCiphertexts = new HashSet<>();
			Map<ByteBuffer, byte[]> authTokenIDToEncryptionKey = new HashMap<>();
			for (DocumentInfo document : this.accessList) {
				// compute auth token
				byte[] authTokenID = F(userKeys[1], document.documentID);
				// compute query ciphertext
				CT_G queryCT = rdh.H(F(document.Kd1, wordToID(keyword)), F(userKeys[0], document.documentID));
				queryCiphertexts.add(SerializationUtils.serialize(new Query<CT_G>(authTokenID, queryCT)));
				authTokenIDToEncryptionKey.put(ByteBuffer.wrap(authTokenID), document.encKey);
			}

			long timeSpentCalculatingMemory = 0;
			long serverStartTime = System.nanoTime();
			if (debug)
				debugPrintf("Search query    bandwidth [user -> server]: %d B\n", 
					MemoryUtil.deepMemoryUsageOf(queryCiphertexts));
			timeSpentCalculatingMemory += ((System.nanoTime() - serverStartTime) / SSEwSU.nano);
			
			// send query ciphertext to server
			Set<ServerResponse> queryResponse = this.server.search(queryCiphertexts);
			// done with server search
			
			long calcStartTime = System.nanoTime();
			if (debug)
				debugPrintf("Search response bandwidth [user <- server]: %d B\n", 
					MemoryUtil.deepMemoryUsageOf(queryResponse) );
			timeSpentCalculatingMemory += ((System.nanoTime() - calcStartTime) / SSEwSU.nano);
			double serverElapsed = ((System.nanoTime() - serverStartTime) / SSEwSU.nano);
			debugPrintf("Server search time: %.2fms\n", 1000 * (serverElapsed - timeSpentCalculatingMemory));
			
			// decrypt response from server
			Collection<String> result = new HashSet<String>(queryResponse.size());
			for (ServerResponse encryptedResponse : queryResponse) {
				String metadata = Decrypt(authTokenIDToEncryptionKey.get(ByteBuffer.wrap(encryptedResponse.authTokenID)), encryptedResponse.yCT);
				result.add(metadata);
			}
			
			double elapsed = ((System.nanoTime() - startTime) / SSEwSU.nano);
			debugPrintf("User search time: %.2fms\n", 1000 * (elapsed - serverElapsed - timeSpentCalculatingMemory));
			return result;
		}
		
		private CT_G makeEditCiphertext(DocumentInfo document, String keyword) throws NoSuchAlgorithmException, UnsupportedEncodingException{
			CT_G editCT = rdh.H(F(document.Kd1, wordToID(keyword)), F(document.KdEdit, userKeys[0]));
			return editCT;
		}
		public void addKeyword(DocumentInfo document, String keyword) throws NoSuchAlgorithmException, UnsupportedEncodingException{
			CT_G editCT = makeEditCiphertext(document, keyword);
			EditQuery<CT_G> editQuery = new EditQuery<CT_G>(F(userKeys[1], document.KdEdit), editCT, document.encryptedMetadata);
			server.addKeyword(editQuery);
		}
		public void removeKeyword(DocumentInfo document, String keyword) throws NoSuchAlgorithmException, UnsupportedEncodingException{
			CT_G editCT = makeEditCiphertext(document, keyword);
			EditQuery<CT_G> editQuery = new EditQuery<CT_G>(F(userKeys[1], document.KdEdit), editCT, null);
			server.removeKeyword(editQuery);
		}

		public void addDocumentInfo(byte[] docID, byte[] docKey, byte[] encKey) {
			this.accessList.add(new DocumentInfo(docID, docKey, null, encKey, null, null));
		}
		public void addDocumentInfo(byte[] docID, byte[] docKey, byte[] encKey, byte[] kdEdit) {
			this.accessList.add(new DocumentInfo(docID, docKey, null, encKey, null, null, kdEdit));
		}

	}

	static class DocumentInfo {
		private byte[] documentID;
		private byte[] Kd1;
		private byte[] Kd2;
		private byte[] encKey;
		private byte[] encryptedMetadata;
		private byte[] Kd2Enc;
		private byte[] KdEdit;

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

	@SuppressWarnings("serial")
	public static class UserAlreadyExists extends Exception {
		String username;
		UserAlreadyExists(String username) { this.username = username; }
	}

	@SuppressWarnings("serial")
	public static class UserDoesntExist extends Exception {
		String username;
		UserDoesntExist(String username) { this.username = username; }
	}

	@SuppressWarnings("serial")
	public static class DocumentDoesntExist extends Exception {
		String name;
		DocumentDoesntExist(String name) { this.name = name; }
	}

	public byte[] documentNameToID(String documentName) throws NoSuchAlgorithmException {
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		byte[] hash = digest.digest(documentName.getBytes());
		return Arrays.copyOf(hash, idLengthBytes);
	}

	public byte[] wordToID(String word) throws NoSuchAlgorithmException {
		return documentNameToID(word);
	}
	
	public void debugPrintf(String format, Object... args) {
		if (debug) {
			synchronized (System.out) {
				System.out.printf(format, args);
			}
		}
	}

}
