package org.crypto.sse.SSEwSU;

import java.io.IOException;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.concurrent.ExecutionException;

import javax.crypto.NoSuchPaddingException;

import org.crypto.sse.CryptoPrimitives.RewritableDeterministicHash;

import com.google.common.collect.Multimap;

public interface Manager<CT_G extends Serializable, RDH extends RewritableDeterministicHash<CT_G>> {

	void setup(Server<CT_G, RDH> server, Multimap<String, String> mm)
			throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			NoSuchProviderException, NoSuchPaddingException, IOException, InterruptedException, ExecutionException;

	User<CT_G, RDH> enroll(String username) throws Manager.UserAlreadyExists;

	void shareDoc(String documentName, String username, boolean allowEdit)
			throws Manager.UserDoesntExist, Manager.DocumentDoesntExist, UnsupportedEncodingException;

	void shareDoc(String documentName, String username)
			throws Manager.UserDoesntExist, Manager.DocumentDoesntExist, UnsupportedEncodingException;

	void unshareDoc(String documentName, String username)
			throws Manager.UserDoesntExist, Manager.DocumentDoesntExist, UnsupportedEncodingException;
	

	@SuppressWarnings("serial") 
	class UserAlreadyExists extends Exception {
		String username;
		UserAlreadyExists(String username) { this.username = username; }
	}

	@SuppressWarnings("serial") class UserDoesntExist extends Exception {
		String username;
		UserDoesntExist(String username) { this.username = username; }
	}

	@SuppressWarnings("serial") class DocumentDoesntExist extends Exception {
		String name;
		DocumentDoesntExist(String name) { this.name = name; }
	}

}