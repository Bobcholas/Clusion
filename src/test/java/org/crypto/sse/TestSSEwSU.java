package org.crypto.sse;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
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
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.crypto.sse.CryptoPrimitives.RewritableDeterministicHash;
import org.crypto.sse.SSEwSU.DocumentDoesntExist;
import org.crypto.sse.SSEwSU.UserAlreadyExists;
import org.crypto.sse.SSEwSU.UserDoesntExist;

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
	
	public static class ECPointWrapper implements Serializable {

		private static final long serialVersionUID = 3405642266930273962L;
		private transient String  _curveName;
		private transient ECPoint _point;

		public ECPointWrapper(ECPoint point, String curveName) {
			_point = point;
			_curveName = curveName;
		}
		
		private void readObject(ObjectInputStream aInputStream) throws ClassNotFoundException, IOException
	    {      
			aInputStream.defaultReadObject();
			_curveName = aInputStream.readUTF();
			ECCurve curve = ECNamedCurveTable.getParameterSpec(_curveName).getCurve();
			int len = aInputStream.readInt();
	        byte[] b = new byte[len];
	        aInputStream.read(b);
	        _point = curve.decodePoint(b);
	    }
	 
	    private void writeObject(ObjectOutputStream aOutputStream) throws IOException
	    {
	    	aOutputStream.defaultWriteObject();
	    	aOutputStream.writeUTF(_curveName);
	        byte[] bs = _point.getEncoded(true);
	        aOutputStream.writeInt(bs.length);
	        aOutputStream.write(bs);
        }
	    
	    @Override
	    public int hashCode() {
	        return _curveName.hashCode() ^ _point.hashCode();
	    }

	    @Override
	    public boolean equals(Object obj) {
	    	ECPointWrapper ecp = (ECPointWrapper) obj;
	        return _curveName.equals(ecp._curveName) && _point.equals(ecp._point);
	    }
	}
	
	public static class ECRDH2 implements RewritableDeterministicHash<ECPointWrapper> 
	{
		public final BigInteger fieldOrder;
		public final ECPoint generator;
		public final String curveName;
		
		/**
		 * Note that the security parameter depends on which elliptic curve is used; its length is the security parameter's length.
		 * @param params The elliptic curve to use.
		 */
		ECRDH2(ECNamedCurveParameterSpec params) { 
			this.curveName = params.getName();
			this.fieldOrder = params.getN();
			this.generator = params.getG().multiply(new BigInteger(CryptoPrimitives.randomBytes(params.getCurve().getFieldSize())).mod(fieldOrder));
		}

		@Override
		public ECPointWrapper H(byte[] A, byte[] B) {
			BigInteger tmp = new BigInteger(A);
			BigInteger tmp2 = new BigInteger(B);
			return new ECPointWrapper(generator.multiply(tmp.multiply(tmp2).mod(fieldOrder)), curveName);
		}

		@Override
		public byte[] GenToken(byte[] C, byte[] D) {
			BigInteger tmp = new BigInteger(C);
			BigInteger tmp2 = new BigInteger(D);
			return (tmp.multiply(tmp2.modInverse(fieldOrder))).mod(fieldOrder).toByteArray();
		}

		@Override
		public ECPointWrapper Apply(ECPointWrapper ct, byte[] token) {
			return new ECPointWrapper(ct._point.multiply(new BigInteger(token)), curveName);
		}

		@Override
		public BigInteger getFieldOrder() {
			return this.fieldOrder;
		}
		
	}

	public static void main(String[] args) 
			throws InvalidKeyException, InvalidAlgorithmParameterException, 
			NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, 
			InvalidKeySpecException, IOException, InterruptedException, ExecutionException, UserAlreadyExists, UserDoesntExist, DocumentDoesntExist {

		BufferedReader input = new BufferedReader(new InputStreamReader(System.in));

		System.out.print("Enter the relative path name of the folder that contains the files to make searchable: ");
		String pathName = input.readLine();

		ArrayList<File> listOfFile = new ArrayList<File>();
		TextProc.listf(pathName, listOfFile);
		TextProc.TextProc(false, pathName);

		// Construction of the global multi-map
		System.out.println("\nBeginning of Encrypted Multi-map creation \n");

		final int securityParameter = 256;
		 ECRDH2 ecrdh = new ECRDH2(ECNamedCurveTable.getParameterSpec("curve25519")); 
		 
		//		NaiveRDH rdh = new NaiveRDH(securityParameter);
		//		SSEwSU<ByteBuffer, NaiveRDH> sse = new SSEwSU<ByteBuffer, NaiveRDH>(TextExtractPar.lp2, rdh, securityParameter);
		SSEwSU<ECPointWrapper, ECRDH2> sse = new SSEwSU<ECPointWrapper, ECRDH2>(TextExtractPar.lp2, ecrdh, securityParameter);
		
		System.out.printf("Number of unique words: %d\n", TextExtractPar.lp1.keySet().size());

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
				} catch (UserAlreadyExists e) {
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
				} catch (UserDoesntExist | DocumentDoesntExist e) {
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
