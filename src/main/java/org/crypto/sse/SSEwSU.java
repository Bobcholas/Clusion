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
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
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
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.crypto.sse.CryptoPrimitives.ECRDH;

import com.google.common.collect.Multimap;
import com.javamex.classmexer.MemoryUtil;

public class SSEwSU {

	public final static String START_STRING = "STARTSTRING";
	public final static int idLengthBytes = 128 / 8;
	public final static double nano = 1000000000.0;
	public final static int AES_IV_LENGTH = 16;
	public final static int METADATA_LENGTH = 256;
	private final static boolean debug = true;

	public final int securityParameter;
	public final ECRDH rdh;
	
	private Server server;
	private Manager manager;
	
	private static final ECCurve curve = ECNamedCurveTable.getParameterSpec("secp224r1").getCurve();

	public SSEwSU(Multimap<String, String> mm, int securityParameter) 
			throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException, InterruptedException, ExecutionException {
		
		this.securityParameter = securityParameter;
		this.rdh = new ECRDH(ECNamedCurveTable.getParameterSpec("secp224r1")); //rdh;

		this.server = new Server();
		this.manager = new Manager();
		
//		long startTime = System.nanoTime();
		this.manager.setup(this.server, mm);
//		double elapsed = ((System.nanoTime() - startTime) / nano);
//		System.out.println(String.format("Setup took %.2fms", 1000 * elapsed));
//		System.out.println(String.format("%d document word pairs inserted [%.4fms/pair]\n%d total documents", 
//				this.server.encryptedMM.size(), 
//				1000 * elapsed / this.server.encryptedMM.size(),
//				this.manager.documents.size()));
		
//		long serverSize = MemoryUtil.deepMemoryUsageOf(this.server) / 1024 / 1024;
//		System.out.printf("Server memory usage: %d MB\n", serverSize);
//		TestSSEwSU.debugOutput.write(String.format("SERVER SIZE: %d MB\n", serverSize));
//		TestSSEwSU.debugOutput.write(String.format("SERVER UPLOAD TIME: %.2fms\n", 1000 * elapsed));
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
//		debugPrintf("User %s has access to %d files\n", username, 
//				this.manager.users.get(username).accessList.size());
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
		//TODO: this has slight bias in randomness (or lots if field order is larger than HMAC order); look into another way?
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

	class Query implements Serializable {
		private static final long serialVersionUID = -1891843663804523275L;
		private transient byte[] authTokenID;
		private transient ECPoint queryCiphertext;

		Query(byte[] tokID, ECPoint ct) {
			this.authTokenID = tokID;
			this.queryCiphertext = ct;
		}
		
		private void readObject(ObjectInputStream aInputStream) throws ClassNotFoundException, IOException
	    {      
	        int len = aInputStream.readInt();
	        authTokenID = new byte[len];
	        aInputStream.read(authTokenID);
	        len = aInputStream.readInt();
	        byte[] b = new byte[len];
	        aInputStream.read(b);
	        queryCiphertext = curve.decodePoint(b);
	    }
	 
	    private void writeObject(ObjectOutputStream aOutputStream) throws IOException
	    {
	        aOutputStream.writeInt(authTokenID.length);
	        aOutputStream.write(authTokenID);
	        byte[] bs = queryCiphertext.getEncoded(true);
	        aOutputStream.writeInt(bs.length);
	        aOutputStream.write(bs);
        }
	}
	class EditQuery {
		byte[] authTokenID;
		ECPoint queryCiphertext;
		byte[] encryptedMetadata;

		EditQuery(byte[] tokID, ECPoint ct, byte[] encryptedMetadata) {
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
		Map<ECPoint, byte[]> encryptedMM;
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
		
		public void setup(Map<ECPoint, byte[]> encryptedMM) {
			this.encryptedMM = encryptedMM;
			this.authTokenMap = new HashMap<ByteBuffer, byte[]>();
			if (editPerms){
				this.authTokenEditMap = new HashMap<ByteBuffer, byte[]>();
			}
		}

		public Set<ServerResponse> search(Set<byte[]> queryCiphertexts) {			
			Set<ServerResponse> resultSet = new HashSet<ServerResponse>();
			for (byte[] qCT : queryCiphertexts) {
				Query query = (SSEwSU.Query) SerializationUtils.deserialize(qCT);
				byte[] authToken = authTokenMap.get(ByteBuffer.wrap(query.authTokenID));
				if (authToken == null) {
					continue;
				}

				ECPoint xCT = rdh.Apply(query.queryCiphertext, authToken);
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
		public void addKeyword(EditQuery query) {
			//TODO: Where does metadata come from? Presumably needs to be recalculated...
			byte[] authTokenEdit = authTokenEditMap.get(ByteBuffer.wrap(query.authTokenID));
			if (authTokenEdit == null){ //not authorized
				return;
			}
			ECPoint newKeywordToken = rdh.Apply(query.queryCiphertext, authTokenEdit);
			encryptedMM.put(newKeywordToken, query.encryptedMetadata);
		}
		public void removeKeyword(EditQuery query) {
			byte[] authTokenEdit = authTokenEditMap.get(ByteBuffer.wrap(query.authTokenID));
			if (authTokenEdit == null){ //not authorized
				return;
			}
			ECPoint newKeywordToken = rdh.Apply(query.queryCiphertext, authTokenEdit);
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
				System.out.println("Thread #" + (i + 1) + " gets " + tmp.size() + " pairs");
			}

			System.out.println("End of Partitioning\n");

			Map<ECPoint, byte[]> encryptedMM = new HashMap<ECPoint, byte[]>();
			List<Future<Map<ECPoint, byte[]>>> futures = new ArrayList<>();
			for (final Collection<Entry<String,String>> input : inputs) {
				Callable<Map<ECPoint, byte[]>> callable = 
						new Callable<Map<ECPoint, byte[]>>() {
					
					public Map<ECPoint, byte[]> call() throws Exception {
						return encryptDocWords(input);
					}
					
				};
				futures.add(service.submit(callable));
			}

			service.shutdown();

			for (Future<Map<ECPoint, byte[]>> future : futures) {
				encryptedMM.putAll(future.get());
			}
			
			// TODO randomize order of map (?)

			// send encrypted map to server
			this.server.setup(encryptedMM);
			

//			long serverSize = MemoryUtil.deepMemoryUsageOf(encryptedMM) / 1024;
//			TestSSEwSU.debugOutput.write(String.format("Server upload bandwidth: %d kB\n", serverSize));
		}
		
		public Map<ECPoint, byte[]> encryptDocWords(final Collection<Entry<String,String>> documentWordPairs) 
				throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException {
			
			// Build encrypted map from corpus of documents
			int i = 0;
			Map<ECPoint, byte[]> encryptedMM = new HashMap<ECPoint, byte[]>();
			for (Entry<String,String> docWord : documentWordPairs) {
				String documentName = docWord.getKey();
				String word = docWord.getValue();
				DocumentInfo document = documents.get(documentName);
			
				ECPoint xCT = rdh.H(document.Kd2Enc, F(document.Kd1, wordToID(word)));
				encryptedMM.put(xCT, document.encryptedMetadata);
				
				if ((i++ % 2500) == 0) {
					synchronized (System.out) {
					System.out.println("Thread " + Thread.currentThread().getId() + " is " + 
							(100 * i)/documentWordPairs.size() + "% done "
									+ "[" + i + "/" + documentWordPairs.size() + "]"); 
					}
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
			return null;
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
//			long startTime = System.nanoTime();
			
			Set<byte[]> queryCiphertexts = new HashSet<>();
			Map<ByteBuffer, byte[]> authTokenIDToEncryptionKey = new HashMap<>();
			for (DocumentInfo document : this.accessList) {
				// compute auth token
				byte[] authTokenID = F(userKeys[1], document.documentID);
				// compute query ciphertext
				ECPoint queryCT = rdh.H(F(document.Kd1, wordToID(keyword)), F(userKeys[0], document.documentID));
				queryCiphertexts.add(SerializationUtils.serialize(new Query(authTokenID, queryCT)));
				authTokenIDToEncryptionKey.put(ByteBuffer.wrap(authTokenID), document.encKey);
			}

			// send query ciphertext to server
//			long timeSpentCalculatingMemory = 0;
//			long serverStartTime = System.nanoTime();
//			debugPrintf("Search query    bandwidth [user -> server]: %d B\n", 
//					MemoryUtil.deepMemoryUsageOf(queryCiphertexts) );
//			TestSSEwSU.debugOutput.write(String.format("BANDWIDTH: %d\t%d\n", 
//					queryCiphertexts.size(), MemoryUtil.deepMemoryUsageOf(queryCiphertexts)));
//			timeSpentCalculatingMemory += ((System.nanoTime() - serverStartTime) / SSEwSU.nano);
			Set<ServerResponse> queryResponse = this.server.search(queryCiphertexts);
//			long calcStartTime = System.nanoTime();
//			debugPrintf("Search response bandwidth [user <- server]: %d B\n", 
//					MemoryUtil.deepMemoryUsageOf(queryResponse) );
//			timeSpentCalculatingMemory += ((System.nanoTime() - calcStartTime) / SSEwSU.nano);
//			double serverElapsed = ((System.nanoTime() - serverStartTime) / SSEwSU.nano);
//			debugPrintf("Server search time: %.2fms\n", 1000 * (serverElapsed - timeSpentCalculatingMemory));
//			TestSSEwSU.debugOutput.write(String.format("SERVER SEARCH TIME: %d\t%.2fms\n", 
//					queryCiphertexts.size(), 1000 * (serverElapsed - timeSpentCalculatingMemory)));
			// decrypt response from server
			Collection<String> result = new HashSet<String>(queryResponse.size());
			for (ServerResponse encryptedResponse : queryResponse) {
				String metadata = Decrypt(authTokenIDToEncryptionKey.get(ByteBuffer.wrap(encryptedResponse.authTokenID)), encryptedResponse.yCT);
				result.add(metadata);
			}
//			double elapsed = ((System.nanoTime() - startTime) / SSEwSU.nano);
//			debugPrintf("User search time: %.2fms\n", 1000 * (elapsed - serverElapsed - timeSpentCalculatingMemory));
//			TestSSEwSU.debugOutput.write(String.format("SERVER SEARCH TIME: %d\t%.2fms\n", 
//					queryCiphertexts.size(), 1000 * (elapsed - serverElapsed - timeSpentCalculatingMemory)));
			return result;
		}
		
		private ECPoint makeEditCiphertext(DocumentInfo document, String keyword) throws NoSuchAlgorithmException, UnsupportedEncodingException{
			ECPoint editCT = rdh.H(F(document.Kd1, wordToID(keyword)), F(document.KdEdit, userKeys[0]));
			return editCT;
		}
		public void addKeyword(DocumentInfo document, String keyword) throws NoSuchAlgorithmException, UnsupportedEncodingException{
			ECPoint editCT = makeEditCiphertext(document, keyword);
			EditQuery editQuery = new EditQuery(F(userKeys[1], document.KdEdit), editCT, document.encryptedMetadata);
			server.addKeyword(editQuery);
		}
		public void removeKeyword(DocumentInfo document, String keyword) throws NoSuchAlgorithmException, UnsupportedEncodingException{
			ECPoint editCT = makeEditCiphertext(document, keyword);
			EditQuery editQuery = new EditQuery(F(userKeys[1], document.KdEdit), editCT, null);
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
			System.out.printf(format, args);
		}
	}

}
