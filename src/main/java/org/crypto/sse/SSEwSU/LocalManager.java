package org.crypto.sse.SSEwSU;

import java.io.IOException;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import javax.crypto.NoSuchPaddingException;

import org.crypto.sse.CryptoPrimitives;
import org.crypto.sse.CryptoPrimitives.RewritableDeterministicHash;

import com.google.common.collect.Multimap;
import com.javamex.classmexer.MemoryUtil;

class LocalManager<CT_G extends Serializable, RDH extends RewritableDeterministicHash<CT_G>> implements Manager<CT_G, RDH> {

	Map<String, User<CT_G, RDH>> users;
	Map<String, DocumentInfo> documents;
	private byte[][] masterKeys;
	private Server<CT_G, RDH> server;
	private final boolean editPerms;
	private SSEwSUSettings<CT_G, RDH> settings;

	LocalManager(SSEwSUSettings<CT_G, RDH> settings, boolean edit) {
		this.settings = settings;
		this.editPerms = edit;
		users = new HashMap<String, User<CT_G, RDH>>();
		documents = new HashMap<String, DocumentInfo>();
		//masterKeys: mk[0] for kd, mk[1] ~kd (kd2), mk[2] used for enc, mk[3] optionally used for edit rights
		if (!edit){
			masterKeys = new byte[3][];
		} else {
			masterKeys = new byte[4][];
		}
	}
	LocalManager(SSEwSUSettings<CT_G, RDH> settings) { //default to no edit
		this(settings, false);
	}
	
	@Override
	public void setup(Server<CT_G, RDH> server, final Multimap<String, String> mm) 
			throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, 
			NoSuchProviderException, NoSuchPaddingException, IOException, InterruptedException, ExecutionException {
		
		this.server = server;
		
		// select master keys (3, or 4 if editing)
		for (int i = 0; i < masterKeys.length; ++i)
			masterKeys[i] = CryptoPrimitives.randomBytes(settings.getSecurityParameter());
		
		for (String documentName : mm.keySet()) {
			byte[] docID = settings.documentNameToID(documentName);
			byte[] kd2 = settings.F(masterKeys[1], docID);
			byte[] encKey = settings.G(masterKeys[2], docID);
			DocumentInfo document;
			if (editPerms) {
				byte[] kdEdit = settings.F(masterKeys[3], docID);
				document = 
						new DocumentInfo(docID,
								settings.F(masterKeys[0], docID),
								kd2,
								encKey,
								settings.Encrypt(encKey, documentName),
								settings.F(kd2, docID),
								kdEdit);
			}else{
				document = 
						new DocumentInfo(docID,
								settings.F(masterKeys[0], docID),
								kd2,
								encKey,
								settings.Encrypt(encKey, documentName),
								settings.F(kd2, docID));
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
			if (settings.isDebug())
				System.out.printf("Thread #" + (i + 1) + " gets " + tmp.size() + " pairs\n");
		}

		if (settings.isDebug())
			System.out.printf("End of Partitioning\n");

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
		

		if (settings.isDebug()) {
			long serverSize = MemoryUtil.deepMemoryUsageOf(encryptedMM) / 1024;
			System.out.printf("Server upload bandwidth: %d kB\n", serverSize);
		}
	}
	
	private Map<CT_G, byte[]> encryptDocWords(final Collection<Entry<String,String>> documentWordPairs) 
			throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException {
		
		// Build encrypted map from corpus of documents
		int i = 0;
		Map<CT_G, byte[]> encryptedMM = new HashMap<CT_G, byte[]>();
		for (Entry<String,String> docWord : documentWordPairs) {
			String documentName = docWord.getKey();
			String word = docWord.getValue();
			DocumentInfo document = documents.get(documentName);
		
			CT_G xCT = settings.getRDH().H(document.Kd2Enc, settings.F(document.Kd1, settings.wordToID(word)));
			encryptedMM.put(xCT, document.encryptedMetadata);
			
			if ((i++ % 2500) == 0) {
				if (settings.isDebug()) 
					System.out.printf("Thread %d is %.2f%% done [%d/%d]\n",
						Thread.currentThread().getId(), 
						(double) (100.0 * (double)i)/documentWordPairs.size(),
						i, documentWordPairs.size()); 
			}
		}
		return encryptedMM;
	}

	@Override
	public User<CT_G, RDH> enroll(String username) throws Manager.UserAlreadyExists {
		if (users.containsKey(username)) {
			throw new Manager.UserAlreadyExists(username);
		}

		// generate keys for user
		User<CT_G, RDH> newUser = new User<CT_G, RDH>(username, new byte[][] {
			CryptoPrimitives.randomBytesBuffered(settings.getSecurityParameter()),
			CryptoPrimitives.randomBytesBuffered(settings.getSecurityParameter())
		}, server);
		users.put(username, newUser);
		return newUser;
	}

	@Override
	public void shareDoc(String documentName, String username, boolean allowEdit) throws Manager.UserDoesntExist, Manager.DocumentDoesntExist, UnsupportedEncodingException {
		if (!users.containsKey(username)) 
			throw new Manager.UserDoesntExist(username);

		if (!documents.containsKey(documentName))
			throw new Manager.DocumentDoesntExist(documentName);
		
		if (allowEdit && !this.editPerms){
			throw new IllegalStateException("Edit permissions not enabled");
		}

		User<CT_G, RDH> user = users.get(username);
		DocumentInfo document = documents.get(documentName);

		// compute authorization token
		byte[] authToken = settings.getRDH().GenToken(settings.F(document.Kd2, document.documentID), settings.F(user.userKeys[0], document.documentID));
		// compute authorization token id
		byte[] authTokenID = settings.F(user.userKeys[1], document.documentID);

		if (allowEdit){
			byte[] authTokenEdit = settings.getRDH().GenToken(settings.F(document.Kd2, document.documentID), settings.F(user.userKeys[0], document.KdEdit));
			// compute authorization token id
			byte[] authTokenIDEdit = settings.F(user.userKeys[1], document.KdEdit);
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
	@Override
	public void shareDoc(String documentName, String username) throws Manager.UserDoesntExist, Manager.DocumentDoesntExist, UnsupportedEncodingException {
		shareDoc(documentName, username, false);
	}

	@Override
	public void unshareDoc(String documentName, String username) throws Manager.UserDoesntExist, Manager.DocumentDoesntExist, UnsupportedEncodingException {
		if (!users.containsKey(username)) 
			throw new Manager.UserDoesntExist(username);

		if (!documents.containsKey(documentName))
			throw new Manager.DocumentDoesntExist(documentName);

		User<CT_G, RDH> user = users.get(username);
		DocumentInfo document = documents.get(documentName);

		byte[] authTokenID = settings.F(user.userKeys[1], document.documentID);
		this.server.removeAccess(authTokenID);
		
		if (this.editPerms){
			byte[] authTokenIDEdit = settings.F(user.userKeys[1], document.KdEdit);
			this.server.removeEditAccess(authTokenIDEdit);
		}
	}

}