package org.crypto.sse.SSEwSU;

import java.io.Serializable;

import org.crypto.sse.CryptoPrimitives.RewritableDeterministicHash;

public interface SSEwSUSettings<CT_G extends Serializable, RDH extends RewritableDeterministicHash<CT_G>> {
	/**
	 * Wrapper to calculate HMAC with results taken from integers mod p, for prime p which is also the order of the RDH
	 * @param key Key for the HMAC
	 * @param x Message to calculate for
	 * @return The result, on the interval [0, p).
	 * @throws UnsupportedEncodingException 
	 */
	public byte[] F(byte[] key, byte[] x);

	/**
	 * Wrapper to calculate an HMAC (keyed pseudorandom function)
	 * @param key Key of HMAC
	 * @param x Message to calculate for
	 * @return The HMAC output
	 * @throws UnsupportedEncodingException 
	 */
	public byte[] G(byte[] key, byte[] x);

	public byte[] Encrypt(byte[] key, String plaintext);
	public String Decrypt(byte[] key, byte[] ciphertext);

	public RDH getRDH();
	public int getSecurityParameter();

	public byte[] wordToID(String keyword);
	public byte[] documentNameToID(String documentName);
	
	public boolean isDebug();
}
