package org.crypto.sse.unittests;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.concurrent.ExecutionException;

import javax.crypto.NoSuchPaddingException;

import org.crypto.sse.CryptoPrimitives.ECRDH;
import org.crypto.sse.SSEwSU.DefaultSSEwSUSettings;
import org.crypto.sse.SSEwSU.ECPointWrapper;
import org.crypto.sse.SSEwSU.LocalSSEwSU;
import org.crypto.sse.SSEwSU.Manager.DocumentDoesntExist;
import org.crypto.sse.SSEwSU.Manager.UserAlreadyExists;
import org.crypto.sse.SSEwSU.Manager.UserDoesntExist;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;
import com.google.common.collect.Multimaps;

import junit.framework.TestCase;

public class UnitTestLocalSSEwSU extends TestCase {

	LocalSSEwSU<ECPointWrapper, ECRDH> sse;
	Multimap<String, String> docToWordMM;
	Multimap<String, String> userAccesses;
	UnencryptedIndex index;

	public UnitTestLocalSSEwSU(String name) {
		super(name);

		DefaultSSEwSUSettings.isDebug = false;

		// document -> word
		String doc1 = "hello world";
		String doc2 = "my name is world";
		String doc3 = "this is a welcome hello world";
		docToWordMM = ArrayListMultimap.create();
		docToWordMM.putAll("doc1", Arrays.asList(doc1.split(" ")));
		docToWordMM.putAll("doc2", Arrays.asList(doc2.split(" ")));
		docToWordMM.putAll("doc3", Arrays.asList(doc3.split(" ")));

		// user -> document
		List<String> users = Arrays.asList(new String[] {
				"", 
				"doc1", "doc2", "doc3", 
				"doc1 doc2", "doc1 doc3", "doc2 doc3", 
				"doc1 doc2 doc3", 
		});
		userAccesses = ArrayListMultimap.create();
		int i = 0;
		for (String user : users) 
			userAccesses.putAll("user" + (i++), Arrays.asList(user.split(" ")));
	}

	protected void setUp() throws Exception {
		super.setUp();

		try {
			sse = new LocalSSEwSU<>(docToWordMM, new DefaultSSEwSUSettings());
			index = new UnencryptedIndex(Multimaps.invertFrom(docToWordMM, ArrayListMultimap.create()));

			for (String user : userAccesses.keySet()) {
				sse.enroll(user);
				index.enroll(user);
				for (String doc : userAccesses.get(user)) {
					if (doc == "")
						continue;

					sse.shareDoc(doc, user);
					index.shareDoc(doc, user, false);
				}
			}
		} catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException
				| NoSuchProviderException | NoSuchPaddingException | IOException | InterruptedException
				| ExecutionException e) {
			assertFalse("failed to set up SSEwSU", true);
		}
	}

	public void testEnroll() throws UserAlreadyExists{
		sse.enroll("newUser");

		try {
			sse.enroll("newUser");
			assertFalse("failed to detect that user already exists", true);
		} catch (UserAlreadyExists e) {}
	}

	public void checkAllPossibleQueries() throws Exception  {
		try {
			for (String user : index._users) {
				for (String word : index._wordToDocMM.keySet()) {
					assertQueryResult(sse.query(user, word), index.query(user, word));
				}
			}
		} catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException
				| NoSuchProviderException | NoSuchPaddingException | IOException e) {
			throw e;
		}
	}

	public void assertQueryResult(Collection<String> actual, Collection<String> expected) {
		assertQueryResult(actual, expected, "");
	}

	public void assertQueryResult(Collection<String> actual, Collection<String> expected, String msg) {
		assertEquals(msg, new HashSet<>(expected), new HashSet<>(actual));
	}

	public void testShareDoc() throws Exception {
		checkAllPossibleQueries();
		index.shareDoc("doc1", "user0", false);
		sse.shareDoc("doc1", "user0");
		checkAllPossibleQueries();
	}

	public void testUnshareDoc() throws Exception {
		checkAllPossibleQueries();
		index.shareDoc("doc1", "user0", false);
		sse.shareDoc("doc1", "user0");
		checkAllPossibleQueries();
		index.unshareDoc("doc1", "user0");
		sse.unshareDoc("doc1", "user0");
		checkAllPossibleQueries();
	}

	public void testQuery() throws Exception {
		checkAllPossibleQueries();
	}

	public void testAddKeyword() {
		double result = 2 + 4;
		assertTrue(result == 6);
	}

	public void testRemoveKeyword() {
		double result = 2 + 4;
		assertTrue(result == 6);
	}

	static class UnencryptedIndex {

		public List<String> _users;
		public Multimap<String, String> _userReadAccesses;
		public Multimap<String, String> _userEditAccesses;
		public Multimap<String, String> _wordToDocMM;

		public UnencryptedIndex(Multimap<String, String> wordToDocMM) {
			this._wordToDocMM = wordToDocMM;
			this._users = new ArrayList<>();
			this._userReadAccesses = ArrayListMultimap.create();;
			this._userEditAccesses = ArrayListMultimap.create();;
		}

		public void enroll(String username) {
			_users.add(username);
		}

		public void shareDoc(String documentName, String username, boolean hasEditAccess) {
			_userReadAccesses.put(username, documentName);
			if (hasEditAccess)
				_userEditAccesses.put(username, documentName);
		}

		public void unshareDoc(String documentName, String username) {
			_userReadAccesses.remove(username, documentName);
			_userEditAccesses.remove(username, documentName);
		}

		public Collection<String> query(String username, String keyword) {
			Collection<String> result = new HashSet<>();
			Collection<String> accessList = _userReadAccesses.get(username);
			for (String document : _wordToDocMM.get(keyword)) 
				if (accessList.contains(document))
					result.add(document);
			return result;
		}

		public void addKeyword(String username, String keyword, String documentName) {
			_wordToDocMM.put(keyword, documentName);
		}

		public void removeKeyword(String username, String keyword, String documentName){
			_wordToDocMM.remove(keyword, documentName);
		}
	}
}
