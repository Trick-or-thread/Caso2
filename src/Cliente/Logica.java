package Cliente;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class Logica {
	
	
	public static final String DES = "DES";
    public static final String AES = "AES";
    public static final String BLOWFISH = "Blowfish";
    public static final String RSA = "RSA";
    public static final String ECIES = "ECIES";
    public static final String RC4 = "RC4";
    public static final String HMACMD5 = "HMACMD5";
    public static final String HMACSHA1 = "HMACSHA1";
    public static final String HMACSHA256 = "HMACSHA256";
    public static final String HMACSHA384 = "HMACSHA384";
    public static final String HMACSHA512 = "HMACSHA512";
    
    
    public static KeyPair grsa() throws NoSuchAlgorithmException {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance(RSA);
        kpGen.initialize(1024, new SecureRandom());
        return kpGen.generateKeyPair();
    }
    
    
    public static X509Certificate gc(KeyPair keyPair) throws OperatorCreationException, CertificateException {
        Calendar endCalendar = Calendar.getInstance();
        endCalendar.add(1, 10);
        X509v3CertificateBuilder x509v3CertificateBuilder = new X509v3CertificateBuilder(new X500Name("CN=localhost"), BigInteger.valueOf(1L), Calendar.getInstance().getTime(), endCalendar.getTime(), new X500Name("CN=localhost"), SubjectPublicKeyInfo.getInstance((Object)keyPair.getPublic().getEncoded()));
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA1withRSA").build(keyPair.getPrivate());
        X509CertificateHolder x509CertificateHolder = x509v3CertificateBuilder.build(contentSigner);
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(x509CertificateHolder);
    }
    
    public static byte[] simetrico(byte[] mensaje, Key llaveSimetrica, String algoritmo, int opcion) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {

    	if(algoritmo.equals(DES) || algoritmo.contentEquals(AES)) {
    		
    		algoritmo = algoritmo + "/ECB/PKCS5Padding";
    		
    	}
    	
    	Cipher descifrador = Cipher.getInstance(algoritmo);
    	
        descifrador.init(opcion, llaveSimetrica);
        
        return descifrador.doFinal(mensaje);
        
    }    
    
    
    public static byte[] asimetrico (byte[] mensaje, Key llave, String algoritmo, int opcion) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
        
    	Cipher decifrador = Cipher.getInstance(algoritmo);
    	
        decifrador.init(opcion, llave);
        
        return decifrador.doFinal(mensaje);
    }

 
    
    public static String toHexString(byte[] array) {
		return DatatypeConverter.printBase64Binary(array);
	}

	public static byte[] toByteArray(String s) {
		return DatatypeConverter.parseBase64Binary(s);
	}
	

}
