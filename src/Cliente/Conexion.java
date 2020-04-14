package Cliente;

import java.net.Socket;
import java.security.KeyPair;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;;

public class Conexion {
	
    private static X509Certificate certificado;
    
    private static KeyPair keyPairCliente;
	
	public final static int PUERTO = 3333;	
	
	public static void main(String[] args) throws Exception {
		
		Socket socket = new Socket("localhost", PUERTO);
		
        Security.addProvider((Provider) new BouncyCastleProvider());
		
		keyPairCliente = Logica.grsa();
		
		certificado = Logica.gc(keyPairCliente);
		
		Intermediario interm = new Intermediario(socket, keyPairCliente, certificado);
		
		interm.inicializar();
		
	}

}
