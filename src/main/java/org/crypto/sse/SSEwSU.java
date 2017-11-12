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
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import java.util.Set;

import javax.crypto.NoSuchPaddingException;

import com.google.common.collect.Multimap;

public class SSEwSU {

	public final static String START_STRING = "STARTSTRING";
	public final static int securityParameter = 128;
	public final static int idLength = 128;
	public final BigInteger fieldOrder;

	public final static double nano = 1000000000.0;
	
	private Server server;
	private Manager manager;

	public SSEwSU(Multimap<String, String> mm) 
			throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException {

		// TODO select random group generator + set up EC
		// TODO genericize ^ to allow for arbitrary rewritable-hash
		fieldOrder = BigInteger.probablePrime(securityParameter, new SecureRandom());
		
		this.server = new Server();
		this.manager = new Manager();
		
		long startTime = System.nanoTime();
		this.manager.setup(this.server, mm);
		double elapsed = ((System.nanoTime() - startTime) / nano);
		System.out.println(String.format("Setup took %.2fms", 1000 * elapsed));
		System.out.println(String.format("%d document word pairs inserted [%.4fms/pair]", 
				this.server.encryptedMM.size(), 1000 * elapsed / this.server.encryptedMM.size()));
	}

	public void enroll(String username) throws UserAlreadyExists {
		this.manager.enroll(username);
	}

	public void shareDoc(String documentName, String username) throws UserDoesntExist, DocumentDoesntExist, UnsupportedEncodingException {
		this.manager.shareDoc(documentName, username);
	}

	public void unshareDoc(String documentName, String username) throws UserDoesntExist, DocumentDoesntExist, UnsupportedEncodingException {
		this.manager.unshareDoc(documentName, username);
	}

	public Collection<String> query(String username, String keyword) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException {
		if (!this.manager.users.containsKey(username)) {
			System.out.println("User " + username + " does not exist");
			return null;
		}
		return this.manager.users.get(username).search(keyword);
	}

	public byte[] F(byte[] key, byte[] x) throws UnsupportedEncodingException { 
		// must be in F_p for prime p
		BigInteger tmp = new BigInteger(CryptoPrimitives.generateHmac(key, x));
		byte[] result = tmp.mod(fieldOrder).toByteArray(); 
//		System.out.println("F(" + Arrays.toString(key) + ", " + Arrays.toString(x) + ") = " + Arrays.toString(result));
		return result;
	}

	public byte[] G(byte[] key, byte[] x) throws UnsupportedEncodingException { 
		byte[] result = CryptoPrimitives.generateHmac(key, x);
//		System.out.println("G(" + Arrays.toString(key) + ", " + Arrays.toString(x) + ") = " + Arrays.toString(result));
		return result;
	}

	public byte[] Encrypt(byte[] key, String x) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException { 
		return CryptoPrimitives.encryptAES_CTR_String(key, CryptoPrimitives.randomBytes(16), x, 40);
	}

	public String Decrypt(byte[] key, byte[] x) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException { 
		return new String(CryptoPrimitives.decryptAES_CTR_String(x, key)); 
	}

	static class Query {
		byte[] authTokenID;
		byte[] queryCiphertext;

		Query(byte[] tokID, byte[] ct) {
			this.authTokenID = tokID;
			this.queryCiphertext = ct;
		}
	}

	class Server {

		// map: EncryptedDocumentWordPair -> EncryptedDocumentMetadata
		Map<ByteBuffer, byte[]> encryptedMM;
		// map: authTokenID -> authToken
		Map<ByteBuffer, byte[]> authTokenMap;

		Server() { }

		public void setup(Map<ByteBuffer, byte[]> encryptedMM) {
			this.encryptedMM = encryptedMM;
			this.authTokenMap = new HashMap<ByteBuffer, byte[]>();
		}

		public Set<byte[]> search(Set<Query> queries) {
			Set<byte[]> resultSet = new HashSet<byte[]>();
			for (Query query : queries) {
				System.out.println("Looking for AuthTokenID: " + Arrays.toString(query.authTokenID));
				byte[] authToken = authTokenMap.get(ByteBuffer.wrap(query.authTokenID));
				if (authToken == null) {
					continue;
				}

				BigInteger tmp = new BigInteger(query.queryCiphertext);
				BigInteger tmp2 = new BigInteger(authToken);
				byte[] xCT = (tmp.multiply(tmp2)).mod(fieldOrder).toByteArray();
				byte[] yCT = encryptedMM.get(ByteBuffer.wrap(xCT));
				if (yCT != null)
					resultSet.add(yCT);
			}
			return resultSet;
		}

		public void giveAccess(byte[] authTokID, byte[] authTok) {
			System.out.println("Added " + Arrays.toString(authTokID) + " to access list");
			authTokenMap.put(ByteBuffer.wrap(authTokID), authTok);
		}

		public void removeAccess(byte[] authTokID) {
			authTokenMap.remove(ByteBuffer.wrap(authTokID));
		}

	}

	class Manager {

		Map<String, User> users;
		private Map<String, DocumentInfo> documents;
		private byte[][] masterKeys;
		private Server server;

		Manager() {
			users = new HashMap<String, User>();
			documents = new HashMap<String, DocumentInfo>();
			masterKeys = new byte[3][];
		}

		
		public void setup(Server server, Multimap<String, String> mm) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException {
			this.server = server;

			// select 3 master keys
			for (int i = 0; i < 3; ++i)
				masterKeys[i] = CryptoPrimitives.randomBytes(securityParameter);

			// set up encrypted map
			Map<ByteBuffer, byte[]> encryptedMM = new HashMap<ByteBuffer, byte[]>();
			/* Building from existing reverse Index
			 * 
			for (String word : mm.keySet()) {
				for (String documentName : mm.get(word)) {
					if (!documents.containsKey(documentName)) {
						byte[] docID = documentNameToID(documentName);
						documents.put(documentName, 
								new DocumentInfo(docID,
										F(masterKeys[0], docID),
										F(masterKeys[1], docID),
										G(masterKeys[2], docID)));
					}
					DocumentInfo document = documents.get(documentName);
					// TODO use EC generator
					BigInteger tmp = new BigInteger(F(document.Kd2, document.documentID));
					BigInteger tmp2 = new BigInteger(F(document.Kd1, wordToID(word)));
					byte[] xCT = (tmp.multiply(tmp2)).mod(fieldOrder).toByteArray();
					byte[] yCT = Encrypt(document.encKey, START_STRING + documentName);
					encryptedMM.put(ByteBuffer.wrap(xCT), yCT);
				}
			}
			*/
			
			// Building from corpus of documents
			for (String documentName : mm.keySet()) {
				byte[] docID = documentNameToID(documentName);
				DocumentInfo document = 
						new DocumentInfo(docID,
							F(masterKeys[0], docID),
							F(masterKeys[1], docID),
							G(masterKeys[2], docID));
				
				documents.put(documentName, document);
				
				for (String word : mm.get(documentName)) {
					// TODO use EC generator
					BigInteger tmp = new BigInteger(F(document.Kd2, document.documentID));
					BigInteger tmp2 = new BigInteger(F(document.Kd1, wordToID(word)));
					byte[] xCT = (tmp.multiply(tmp2)).mod(fieldOrder).toByteArray();
					byte[] yCT = Encrypt(document.encKey, START_STRING + documentName);
					encryptedMM.put(ByteBuffer.wrap(xCT), yCT);
				}
			}
			
			// TODO randomize order of map (?)

			// send encrypted map to server
			this.server.setup(encryptedMM);
		}

		public User enroll(String username) throws UserAlreadyExists {
			if (users.containsKey(username)) {
				throw new UserAlreadyExists(username);
			}

			// generate keys for user
			User newUser = new User(username, new byte[][] {
				CryptoPrimitives.randomBytes(securityParameter),
				CryptoPrimitives.randomBytes(securityParameter)
			}, this.server);
			users.put(username, newUser);
			return null;
		}

		public void shareDoc(String documentName, String username) throws UserDoesntExist, DocumentDoesntExist, UnsupportedEncodingException {
			if (!users.containsKey(username)) 
				throw new UserDoesntExist(username);

			if (!documents.containsKey(documentName))
				throw new DocumentDoesntExist(documentName);

			User user = users.get(username);
			DocumentInfo document = documents.get(documentName);

			// compute authorization token
			BigInteger tmp = new BigInteger(F(document.Kd2, document.documentID));
			BigInteger tmp2 = new BigInteger(F(user.userKeys[0], document.documentID));
			byte[] authToken = (tmp.multiply(tmp2.modInverse(fieldOrder))).mod(fieldOrder).toByteArray();

			// compute authorization token id
			byte[] authTokenID = F(user.userKeys[1], document.documentID);

			// send (token id, token) to server
			this.server.giveAccess(authTokenID, authToken);

			// send documentID, Kd, and Kd^enc to user
			user.addDocumentInfo(document.documentID, document.Kd1, document.encKey);
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
		}

	}

	class User {

		private String username;
		private byte[][] userKeys;
		private List<DocumentInfo> accessList;
		private Server server;

		public User(String username, byte[][] keys, Server server) {
			this.username = username;
			this.userKeys = keys;
			this.accessList = new ArrayList<DocumentInfo>();
			this.server = server;
		}

		public Collection<String> search(String keyword) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException {
			Set<Query> queryCiphertexts = new HashSet<>();
			for (DocumentInfo document : this.accessList) {
				// compute auth token
				byte[] authTokenID = F(userKeys[1], document.documentID);
				// compute query ciphertext
				// TODO USE EC
				BigInteger tmp = new BigInteger(F(document.Kd1, wordToID(keyword)));
				BigInteger tmp2 = new BigInteger(F(userKeys[0], document.documentID));
				byte[] queryCT = (tmp.multiply(tmp2)).mod(fieldOrder).toByteArray();

				queryCiphertexts.add(new Query(authTokenID, queryCT));
			}

			// send query ciphertext to server
			Set<byte[]> queryResponse = this.server.search(queryCiphertexts);

			// decrypt response from server
			Collection<String> result = new HashSet<String>();
			for (byte[] encryptedDocMetadata : queryResponse) {
				// HOW TO KNOW WHICH DOCUMENT A RESPONSE IS FOR (in order to decrypt it w/ the right key)
				// need to return docID too?
				// FOR NOW: loop through decryption keys that we have until we find START_STRING
				
				for (DocumentInfo document : this.accessList) {
					String decrypt = Decrypt(document.encKey, encryptedDocMetadata);
					if (decrypt.substring(0, START_STRING.length()).equals(START_STRING)) {
						String metadata = decrypt.substring(START_STRING.length());
						result.add(metadata);
						System.out.println(metadata + " ");
						break;
					}
				}
			}
			return result;
		}

		public void addDocumentInfo(byte[] docID, byte[] docKey, byte[] encKey) {
			this.accessList.add(new DocumentInfo(docID, docKey, null, encKey));
		}

	}

	static class DocumentInfo {
		private byte[] documentID;
		private byte[] Kd1;
		private byte[] Kd2;
		private byte[] encKey;

		DocumentInfo(byte[] docID, byte[] kd1, byte[] kd2, byte[] encKey) {
			this.documentID = docID;
			this.Kd1 = kd1;
			this.Kd2 = kd2;
			this.encKey = encKey;
		}
	}

	public static class UserAlreadyExists extends Exception {
		String username;
		UserAlreadyExists(String username) { this.username = username; }
	}

	public static class UserDoesntExist extends Exception {
		String username;
		UserDoesntExist(String username) { this.username = username; }
	}

	public static class DocumentDoesntExist extends Exception {
		String name;
		DocumentDoesntExist(String name) { this.name = name; }
	}

	public byte[] documentNameToID(String documentName) {
		try {		
			MessageDigest digest;
			digest = MessageDigest.getInstance("SHA-256");
			byte[] hash = digest.digest(documentName.getBytes());
			return Arrays.copyOf(hash, idLength);
			//			return documentName.getBytes();
		} catch (NoSuchAlgorithmException e) {
			return null;
		}
	}

	public byte[] wordToID(String word) {
		return documentNameToID(word);
	}

}
