package org.crypto.sse.SSEwSU;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

public class ECPointWrapper implements Serializable {

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
    
    public String get_curveName() {
		return _curveName;
	}

	public ECPoint get_point() {
		return _point;
	}
}