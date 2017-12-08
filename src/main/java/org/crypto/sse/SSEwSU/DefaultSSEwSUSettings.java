package org.crypto.sse.SSEwSU;

import java.io.IOException;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;

import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.crypto.RuntimeCryptoException;
import org.crypto.sse.CryptoPrimitives;
import org.crypto.sse.CryptoPrimitives.RewritableDeterministicHash;

public class DefaultSSEwSUSettings<CT_G extends Serializable, RDH extends RewritableDeterministicHash<CT_G>> 
	implements SSEwSUSettings<CT_G, RDH> {
	
	public final static int idLengthBytes = 128 / 8;
	public final static double nano = 1000000000.0;
	public final static int AES_IV_LENGTH = 16;
	public final static int METADATA_LENGTH = 256;
	public final static boolean isDebug = true;
	
	private final int securityParameter;
	private final RDH rdh;
	
	public DefaultSSEwSUSettings(int securityParameter, RDH rdh) {
		this.securityParameter = securityParameter;
		this.rdh = rdh;
	}

	@Override
	public byte[] F(byte[] key, byte[] x) { 
		// must be in F_p for prime p
		try {
			BigInteger tmp = new BigInteger(CryptoPrimitives.generateHmac(key, x));
			return tmp.mod(rdh.getFieldOrder()).toByteArray(); 
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeCryptoException(e.getMessage());
		}
	}

	@Override
	public byte[] G(byte[] key, byte[] x) { 
		//note: security parameter here is just parameter of HMAC
		try {
			return CryptoPrimitives.generateHmac(key, x);
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeCryptoException(e.getMessage());
		}
	}

	@Override
	public byte[] Encrypt(byte[] key, String plaintext) { 
		try {
			return CryptoPrimitives.encryptAES_CTR_String(key, CryptoPrimitives.randomBytes(AES_IV_LENGTH), plaintext, METADATA_LENGTH);
		} catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException
				| NoSuchProviderException | NoSuchPaddingException | IOException e) {
			throw new RuntimeCryptoException(e.getMessage());
		}
	}

	@Override
	public String Decrypt(byte[] key, byte[] ciphertext) { 
		try {
			return new String(CryptoPrimitives.decryptAES_CTR_String(ciphertext, key));
		} catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException
				| NoSuchProviderException | NoSuchPaddingException | IOException e) {
			throw new RuntimeCryptoException(e.getMessage());
		} 
	}

	@Override
	public byte[] documentNameToID(String documentName) {
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] hash = digest.digest(documentName.getBytes());
			return Arrays.copyOf(hash, idLengthBytes);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeCryptoException(e.getMessage());
		}
	}

	@Override
	public byte[] wordToID(String word) {
		return documentNameToID(word);
	}

	@Override
	public RDH getRDH() {
		return rdh;
	}

	@Override
	public int getSecurityParameter() {
		return securityParameter;
	}

	@Override
	public boolean isDebug() {
		return isDebug;
	}
}
