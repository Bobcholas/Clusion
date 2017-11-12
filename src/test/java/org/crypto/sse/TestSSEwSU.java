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

import javax.crypto.NoSuchPaddingException;

import org.crypto.sse.SSEwSU;
import org.crypto.sse.SSEwSU.DocumentDoesntExist;
import org.crypto.sse.SSEwSU.UserAlreadyExists;
import org.crypto.sse.SSEwSU.UserDoesntExist;

public class TestSSEwSU {

	static String HELP_TEXT = "Commands: \n"
			+ "> (e)nroll <username>\n"
			+ "> (s)hare <document name> [<username>]+\n"
			+ "> (u)nshare <document name> [<username>]+\n"
			+ "> (q)uery <username> <keyword>\n"
			+ "> [exit|quit]\n"
			+ "> (h)elp\n";

	public static void main(String[] args) 
			throws InvalidKeyException, InvalidAlgorithmParameterException, 
			NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, 
			InvalidKeySpecException, IOException {

		BufferedReader input = new BufferedReader(new InputStreamReader(System.in));
		//
		//		System.out.print("Enter your password : ");
		//		String pass = input.readLine();
		//
		//		// generate keys
		//		List<byte[]> listSK = IEX2Lev.keyGen(256, pass, "salt/salt", 100000);

		System.out.print("Enter the relative path name of the folder that contains the files to make searchable: ");
		String pathName = input.readLine();

		ArrayList<File> listOfFile = new ArrayList<File>();
		TextProc.listf(pathName, listOfFile);

		TextProc.TextProc(false, pathName);

		// Construction of the global multi-map
		System.out.println("\nBeginning of Encrypted Multi-map creation \n");

		SSEwSU sse = new SSEwSU(TextExtractPar.lp1);
		
		System.out.println(HELP_TEXT + "\n");
		System.out.println(TextExtractPar.lp1);

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
						System.out.println("Error: expected format: (e)nroll <username>");
						break;
					}
					String username = splitCommand[1];
					try {
						sse.enroll(username);
						System.out.println("Successfully registered new user: " + username);
					} catch (UserAlreadyExists e) {
						System.out.println("Error: cannot enroll " + username + " user already exists");
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
							sse.shareDoc(documentName, username);
							System.out.println("Successfully Shared " + documentName + " with " + username);
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
							sse.unshareDoc(documentName, username);
							System.out.println("Successfully unshared " + documentName + " with " + username);
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
	
					Collection<String> documentNames = sse.query(username, keyword);
					if (documentNames != null) {
						System.out.print(documentNames.size() + " documents found: ");
						for (String docName : documentNames)
							System.out.print(docName + " ");
						System.out.print("\n");
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
