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
import java.util.Arrays;
import java.util.Collection;
import java.util.concurrent.ExecutionException;

import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.math.ec.ECPoint;
import org.crypto.sse.CryptoPrimitives.ECRDH;
import org.crypto.sse.SSEwSU;
import org.crypto.sse.SSEwSU.DocumentDoesntExist;
import org.crypto.sse.SSEwSU.UserAlreadyExists;
import org.crypto.sse.SSEwSU.UserDoesntExist;

public class TestSSEwSU {

	static String HELP_TEXT = "Commands: \n"
			+ "> (e)nroll [<username>]+\n"
			+ "> (s)hare <document name> [<username>]+\n"
			+ "> (u)nshare <document name> [<username>]+\n"
			+ "> (q)uery <username> <keyword>\n"
			+ "> (a)dd keyword <username> <keyword> <document name>"
			+ "> (r)emove keyword <username> <keyword> <document name>"
			+ "> [exit|quit]\n"
			+ "> (h)elp\n";

	public static void main(String[] args) 
			throws InvalidKeyException, InvalidAlgorithmParameterException, 
			NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, 
			InvalidKeySpecException, IOException, InterruptedException, ExecutionException {

		BufferedReader input = new BufferedReader(new InputStreamReader(System.in));

		System.out.print("Enter the relative path name of the folder that contains the files to make searchable: ");
		String pathName = input.readLine();

		ArrayList<File> listOfFile = new ArrayList<File>();
		TextProc.listf(pathName, listOfFile);

		TextProc.TextProc(false, pathName);

		// Construction of the global multi-map
		System.out.println("\nBeginning of Encrypted Multi-map creation \n");

		final int securityParameter = 128;
		ECRDH ecrdh = new ECRDH(ECNamedCurveTable.getParameterSpec("secp224r1"));

//		NaiveRDH rdh = new NaiveRDH(securityParameter);
//		SSEwSU<ByteBuffer, NaiveRDH> sse = new SSEwSU<ByteBuffer, NaiveRDH>(TextExtractPar.lp2, rdh, securityParameter);
		SSEwSU<ECPoint, ECRDH> sse = new SSEwSU<ECPoint, ECRDH>(TextExtractPar.lp2, ecrdh, securityParameter);

//		System.out.println();
//		System.out.println((new ArrayList<String>(TextExtractPar.lp1.keySet())).subList(0, 20));
//		System.out.println((new ArrayList<String>(TextExtractPar.lp2.keySet())).subList(0, 20));
		
		System.out.println("\n" + HELP_TEXT);

		boolean isDone = false;
		while (!isDone) {
			System.out.print(">> ");
			String command = input.readLine();
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
						} catch (UserAlreadyExists e) {
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
							double elapsed = ((System.nanoTime() - startTime) / SSEwSU.nano);
							System.out.println("[" + String.format("%.2fms", 1000 * elapsed) + 
									"]: Successfully Shared " + names.size() + " documents " + names + " with " + username);
						} catch (UserDoesntExist e) {
							System.out.println("Error: user " + username + " does not exist");
						} catch (DocumentDoesntExist e) {
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
							double elapsed = ((System.nanoTime() - startTime) / SSEwSU.nano);
							System.out.println("[" + String.format("%.2fms", 1000 * elapsed) + 
									"]: Successfully Unshared " + names.size() + " documents " + names + " with " + username);
						} catch (UserDoesntExist e) {
							System.out.println("Error: user " + username + " does not exist");
						} catch (DocumentDoesntExist e) {
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
					double elapsed = ((System.nanoTime() - startTime) / SSEwSU.nano);
					
					if (documentNames != null) {
						System.out.print("[" + String.format("%.2fms", 1000 * elapsed) + "]: " + documentNames.size() + " documents found: ");
						for (String docName : documentNames)
							System.out.print(docName + " ");
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
					double elapsed = ((System.nanoTime() - startTime) / SSEwSU.nano);
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
					double elapsed = ((System.nanoTime() - startTime) / SSEwSU.nano);
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
