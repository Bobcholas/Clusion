package org.crypto.sse;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.concurrent.ExecutionException;

import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.crypto.sse.CryptoPrimitives.ECRDH;
import org.crypto.sse.SSEwSU.DefaultSSEwSUSettings;
import org.crypto.sse.SSEwSU.ECPointWrapper;
import org.crypto.sse.SSEwSU.LocalSSEwSU;
import org.crypto.sse.SSEwSU.Manager;
import org.crypto.sse.SSEwSU.SSEwSUSettings;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;

public class TestSSEwSU {

	static String HELP_TEXT = "Commands: \n"
			+ "> (e)nroll [<username>]+\n"
			+ "> (s)hare <document name> [<username>]+\n"
			+ "> (u)nshare <document name> [<username>]+\n"
			+ "> (q)uery <username> <keyword>\n"
			+ "> (a)dd keyword <username> <keyword> <document name>\n"
			+ "> (r)emove keyword <username> <keyword> <document name>\n"
			+ "> [exit|quit]\n"
			+ "> (h)elp\n";

	public final static boolean isChatCorpus = true;
	
	public static void main(String[] args) 
			throws InvalidKeyException, InvalidAlgorithmParameterException, 
			NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, 
			InvalidKeySpecException, IOException, InterruptedException, ExecutionException, Manager.UserAlreadyExists, Manager.UserDoesntExist, Manager.DocumentDoesntExist {

		BufferedReader input = new BufferedReader(new InputStreamReader(System.in));

		System.out.print("Enter the relative path name of the folder that contains the files to make searchable: ");
		String pathName = input.readLine();

		ArrayList<File> listOfFile = new ArrayList<File>();
		TextProc.listf(pathName, listOfFile);
		TextProc.TextProc(false, pathName);

		// Construction of the global multi-map
		System.out.println("\nBeginning of Encrypted Multi-map creation \n");
		
		LocalSSEwSU<ECPointWrapper, ECRDH> sse = new LocalSSEwSU<>(TextExtractPar.lp2, new DefaultSSEwSUSettings());
		
		System.out.printf("Number of unique words: %d\n", TextExtractPar.lp1.keySet().size());
		System.out.printf("Number of unique documents: %d\n", TextExtractPar.lp2.keySet().size());

		// create users and access permissions if applicable
		if (isChatCorpus) {
			System.out.println("Creating users..\n");
			// mmap : username -> set{filenames to have access to}
			Runtime rt = Runtime.getRuntime();

			Multimap<String, String> userAccesses = ArrayListMultimap.create();
			for (File f : listOfFile) {
				String documentName = f.getAbsolutePath();
				
				String command = "cat " + documentName + " | sed -n 's/.* <\\([^>]*\\)> .*/\\1/p' | sort | uniq";	
				String[] cmd = {
						"/bin/sh",
						"-c",
						command
				};
				Process proc = rt.exec(cmd);
				BufferedReader stdOutput = new BufferedReader(new InputStreamReader(proc.getInputStream()));
				String username = null;
				while ((username = stdOutput.readLine()) != null) {
					userAccesses.put(username, documentName);
				}
			}

			System.out.println(userAccesses.keySet().size() + " unique users found\n");
			int i = 0;
			for (String username : userAccesses.keySet()) {
				try {
					sse.enroll(username);
					if (++i % 2500 == 0)
						System.out.println("enrolling users progress: " + i + "/" + userAccesses.keySet().size() + 
								"[" + ((100.0*i/userAccesses.keySet().size())) + "]");
				} catch (Manager.UserAlreadyExists e) {
					e.printStackTrace();
				}
			}
			i = 0;
			for (String username : userAccesses.keySet()) {
				try {
					for (String documentName : userAccesses.get(username)) {
						sse.shareDoc(documentName, username);
					}
					if (++i % 2500 == 0)
						System.out.println("sharing docs progress: " + i + "/" + userAccesses.keySet().size() + 
								"[" + ((100.0*i/userAccesses.keySet().size())) + "]");
				} catch (Manager.UserDoesntExist | Manager.DocumentDoesntExist e) {
					e.printStackTrace();
				}
			}
			System.out.printf("Created %d users!\n", userAccesses.keySet().size());
		}

		System.out.println("\n" + HELP_TEXT);

		boolean isDone = false;
		
		// begin REPL
		while (!isDone) {
			System.out.print(">> ");
			String command = input.readLine();
			if (command == null)
				break;
			if (command.equals(""))
				continue;

			String[] splitCommand = command.split(" ");
			switch (splitCommand[0]) {
			case "e":
			case "enroll":
			{
				if (splitCommand.length < 2) {
					System.out.println("Error: expected format: (e)nroll [<username>]+");
					break;
				}

				for (int u = 1; u < splitCommand.length; ++u) {
					String username = splitCommand[u];
					try {
						sse.enroll(username);
						System.out.println("Successfully registered new user: " + username);
					} catch (Manager.UserAlreadyExists e) {
						System.out.println("Error: cannot enroll " + username + " user already exists");
					}
				}
			}
			break;
			case "s":
			case "share":
			{
				if (splitCommand.length < 3) {
					System.out.println("Expected format: (s)hare <document name> [<username>]+");
					break;
				}

				String documentName = splitCommand[1];
				for (int u = 2; u < splitCommand.length; ++u) {
					String username = splitCommand[u];
					try {
						long startTime = System.nanoTime();
						Collection<String> names = sse.shareDoc(documentName, username);
						double elapsed = ((System.nanoTime() - startTime) / LocalSSEwSU.nano);
						System.out.println("[" + String.format("%.2fms", 1000 * elapsed) + 
								"]: Successfully Shared " + names.size() + " documents " + names + " with " + username);
					} catch (Manager.UserDoesntExist e) {
						System.out.println("Error: user " + username + " does not exist");
					} catch (Manager.DocumentDoesntExist e) {
						System.out.println("Error: document " + documentName + " does not exist");
					}
				}
			}
			break;
			case "u":
			case "unshare":
			{
				if (splitCommand.length < 3) {
					System.out.println("Expected format: (u)nshare <document name> [<username>]+");
					break;
				}

				String documentName = splitCommand[1];
				for (int u = 2; u < splitCommand.length; ++u) {
					String username = splitCommand[u];
					try {
						long startTime = System.nanoTime();
						Collection<String> names = sse.unshareDoc(documentName, username);
						double elapsed = ((System.nanoTime() - startTime) / LocalSSEwSU.nano);
						System.out.println("[" + String.format("%.2fms", 1000 * elapsed) + 
								"]: Successfully Unshared " + names.size() + " documents " + names + " with " + username);
					} catch (Manager.UserDoesntExist e) {
						System.out.println("Error: user " + username + " does not exist");
					} catch (Manager.DocumentDoesntExist e) {
						System.out.println("Error: document " + documentName + " does not exist");
					}
				}
			}
			break;
			case "q":
			case "query":
			{
				if (splitCommand.length < 3) {
					System.out.println("Error: expected format: (q)uery <username> <keyword>");
					break;
				}

				String username = splitCommand[1];
				String keyword = splitCommand[2];

				long startTime = System.nanoTime();
				Collection<String> documentNames = sse.query(username, keyword);
				double elapsed = ((System.nanoTime() - startTime) / LocalSSEwSU.nano);

				if (documentNames != null) {
					System.out.print("[" + String.format("%.2fms", 1000 * elapsed) + "]: " + documentNames.size() + " documents found: \n");
					for (String docName : documentNames)
						System.out.println("\t" + docName);
					System.out.print("\n");
				}
			}
			break;
			case "a":
			case "add":
			{
				if (splitCommand.length < 4) {
					System.out.println("Error: expected format: (a)dd <username> <keyword> <document name>");
					break;
				}

				String username = splitCommand[1];
				String keyword = splitCommand[2];
				String docName = splitCommand[3];

				long startTime = System.nanoTime();
				boolean success = sse.addKeyword(username, keyword, docName);
				double elapsed = ((System.nanoTime() - startTime) / LocalSSEwSU.nano);
				if (success){
					System.out.println("[" + String.format("%.2fms", 1000 * elapsed) + "]: " + " Keyword added.");
				}else{
					System.out.println("[" + String.format("%.2fms", 1000 * elapsed) + "]: " + " Keyword addition failed.");
				}

			}
			break;
			case "r":
			case "remove":
			{
				if (splitCommand.length < 4) {
					System.out.println("Error: expected format: (r)emove <username> <keyword> <document name>");
					break;
				}

				String username = splitCommand[1];
				String keyword = splitCommand[2];
				String docName = splitCommand[3];

				long startTime = System.nanoTime();
				boolean success = sse.removeKeyword(username, keyword, docName);
				double elapsed = ((System.nanoTime() - startTime) / LocalSSEwSU.nano);
				if (success){
					System.out.println("[" + String.format("%.2fms", 1000 * elapsed) + "]: " + " Keyword added.");
				}else{
					System.out.println("[" + String.format("%.2fms", 1000 * elapsed) + "]: " + " Keyword addition failed.");
				}

			}
			break;
			case "h":
			case "help":
				System.out.println(HELP_TEXT);
				break;
			case "exit": 
			case "quit":
				isDone = true;
				break;
			default:
				System.out.println("Error: Unknown command " + splitCommand[0]);
				break;
			}

		}
	}

}
