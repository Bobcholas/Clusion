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

package org.crypto.sse.SSEwSU;

import java.io.IOException;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Collection;
import java.util.HashSet;
import java.util.concurrent.ExecutionException;
import java.util.regex.Pattern;

import javax.crypto.NoSuchPaddingException;

import org.crypto.sse.CryptoPrimitives.RewritableDeterministicHash;

import com.google.common.collect.Multimap;
import com.javamex.classmexer.MemoryUtil;

public class LocalSSEwSU<CT_G extends Serializable, RDH extends RewritableDeterministicHash<CT_G>> {
	
	public final static double nano = 1000000000.0;
	
	private final SSEwSUSettings<CT_G, RDH> settings;
	private final LocalServer<CT_G, RDH> server;
	private final LocalManager<CT_G, RDH> manager;

	public LocalSSEwSU(Multimap<String, String> mm, SSEwSUSettings<CT_G, RDH> settings) 
			throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException, InterruptedException, ExecutionException {
		
		this.settings = settings;

		this.server = new LocalServer<CT_G, RDH>(settings);
		this.manager = new LocalManager<CT_G, RDH>(settings);
		
		long startTime = System.nanoTime();
		
		this.manager.setup(this.server, mm);
		
		if (settings.isDebug()) {
			double elapsed = ((System.nanoTime() - startTime) / nano);
			System.out.printf("Setup took %.2fms\n", 1000 * elapsed);
			System.out.printf("%d document word pairs inserted [%.4fms/pair]\n%d total documents\n", 
				this.server.encryptedMM.size(), 
				1000 * elapsed / this.server.encryptedMM.size(),
				this.manager.documents.size());
			
//			long serverSizeMB = MemoryUtil.deepMemoryUsageOf(this.server) / 1024 / 1024;
//			System.out.printf("SERVER SIZE: %d MB\n", serverSizeMB);
			System.out.printf("SERVER UPLOAD TIME: %.2fms\n", 1000 * elapsed);
		}
	}

	public void enroll(String username) throws Manager.UserAlreadyExists {
		this.manager.enroll(username);
	}

	public Collection<String> shareDoc(String documentName, String username) throws Manager.UserDoesntExist, Manager.DocumentDoesntExist, UnsupportedEncodingException {
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

	public Collection<String> unshareDoc(String documentName, String username) throws Manager.UserDoesntExist, Manager.DocumentDoesntExist, UnsupportedEncodingException {
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
		if (settings.isDebug())
			System.out.printf("User %s has access to %d files\n", username, 
					this.manager.users.get(username).accessList.size());
		return this.manager.users.get(username).search(keyword);
	}
	
	public Boolean addKeyword(String username, String keyword, String documentName){
		if (!this.manager.users.containsKey(username)) {
			System.out.println("User " + username + " does not exist");
			return null;
		}
		
		User<CT_G, RDH> u = this.manager.users.get(username);
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
		User<CT_G, RDH> u = this.manager.users.get(username);
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

}
