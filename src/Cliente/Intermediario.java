package Cliente;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.KeyPair;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Intermediario {

	public static final String OK = "OK";

	public static final String ALGORITMOS = "ALGORITMOS";

	public static final String SEPARADOR = ":";

	public static final String HOLA = "HOLA";

	public static final String ERROR = "ERROR";

	private Socket conexion;

	private PrintWriter outWriter;

	private BufferedReader inReader;

	private static X509Certificate certificado;

	private static KeyPair keyPairCliente;

	private byte[] byteC;

	public Intermediario(Socket pConexion, KeyPair pKeyPairCliente, X509Certificate pCertificado) throws Exception {

		conexion = pConexion;		

		outWriter = new PrintWriter( conexion.getOutputStream( ), true );

		inReader = new BufferedReader( new InputStreamReader( conexion.getInputStream( ) ) );

		certificado = pCertificado;

		keyPairCliente = pKeyPairCliente;

		byteC = new byte[520];

		byteC = certificado.getEncoded();

	}

	public void inicializar() throws Exception {

		String linea = "";

		// 1 CLIENTE DICE HOLA

		outWriter.println(HOLA);

		System.out.println(">> CLIENTE: "+HOLA);


		// 2 RESPUESTA A HOLA

		linea = inReader.readLine();

		System.out.println(">> SERVIDOR: "+linea);

		if(!linea.equals("OK")) {

			throw new Exception("Respuesta no esperada :v");
		}

		// 3: ALGORITMO IN (DUDA SOBRE SELECCION POR CONSOLA)

		outWriter.println(ALGORITMOS+SEPARADOR+Logica.BLOWFISH+SEPARADOR+Logica.RSA+SEPARADOR+Logica.HMACMD5);

		System.out.println(">> CLIENTE: "+ALGORITMOS+SEPARADOR+Logica.BLOWFISH+SEPARADOR+Logica.RSA+SEPARADOR+Logica.HMACMD5);


		// 4 RESPUESTA ALGORITMO IN

		linea = inReader.readLine();

		System.out.println(">> SERVIDOR: "+linea);

		if(!linea.equals("OK")) {

			throw new Exception("Error en la cadena");
		}

		// 5 CERTIFICADO CLIENTE OUT

		String strCert = Logica.toHexString(byteC);

		outWriter.println(strCert);

		System.out.println(">> CLIENTE: "+strCert);

		// 6 RESPUESTA CERTIFICADO IN

		linea = inReader.readLine();

		System.out.println(">> SERVIDOR: "+linea);

		if(!linea.equals("OK")) {

			throw new Exception("Error en el certificado");
		}

		// 7 CERTIFICADO SERVIDOR IN

		String strCertificadoServer = inReader.readLine();
		
		System.out.println(">> SERVIDOR CERTIFICADO: "+strCertificadoServer);

		byte[] certificadoServerBytes = new byte[520];         

		certificadoServerBytes = Logica.toByteArray(strCertificadoServer);

		CertificateFactory generadorCert = CertificateFactory.getInstance("X.509");

		ByteArrayInputStream in = new ByteArrayInputStream(certificadoServerBytes);

		X509Certificate certificadoServer = (X509Certificate) generadorCert.generateCertificate(in);

		// 8 RESPUESTA CLIENTE OK OUT

		outWriter.println(OK);
		
		System.out.println(">> CLIENTE: OK");

		// 9 RECIBIR LLAVE SIMETRICA IN

		linea = inReader.readLine();
		
		System.out.println(">> SERVIDOR LLAVE SIMETRICA: "+linea);

		byte[] llaveCifrada = Logica.toByteArray(linea);

		byte[] llaveDescifrada = Logica.asimetrico(llaveCifrada, keyPairCliente.getPrivate(),Logica.RSA, Cipher.DECRYPT_MODE);

		SecretKey llaveSimetrica = new SecretKeySpec(llaveDescifrada, Logica.BLOWFISH);

		// 10 RECIBIR RETO DEL SERVIDOR IN

		linea = inReader.readLine();
		
		System.out.println(">> SERVIDOR: RETO: "+linea);

		byte[] retoB = Logica.toByteArray(linea);

		byte[] retoSolucionado = Logica.simetrico(retoB, llaveSimetrica, Logica.BLOWFISH, Cipher.DECRYPT_MODE);

		System.out.println(">> CLIENTE: RETOSOLUCIONADO: "+Logica.toHexString(retoSolucionado));
		
		// 11 ENVIAR RETO ENCRIPTADO CON LLAVE PUBLICA ASIMETRICA OUT

		byte[] retoEncriptado = Logica.asimetrico(retoSolucionado, certificadoServer.getPublicKey(), Logica.RSA, Cipher.ENCRYPT_MODE); 

		outWriter.println(Logica.toHexString(retoEncriptado));
		
		System.out.println(">> CLIENTE ENVIA RETO ENCRIPTADO");

		//12 RESPUESTA SERVIDOR RETO IN

		linea = inReader.readLine();
		
		System.out.println(">> SERVIDOR: "+linea);

		if(!linea.equals("OK")) {

			throw new Exception("Error en el reto");
		}
		
		// 13 ENCRIPTADO SIMETRICO USERNAME OUT
				
		byte[] userByte = Logica.toByteArray("INFRACOMP");
		
		byte[] userEncr = Logica.simetrico(userByte, llaveSimetrica, Logica.BLOWFISH, Cipher.ENCRYPT_MODE);
		
		outWriter.println(Logica.toHexString(userEncr));
		
		System.out.println(">> CLIENTE: INFRACOMP (ENCRIPTADO)");
		
		//14 RECIBIR FECHA IN
	
		linea = inReader.readLine();
		
		System.out.println(">> SERVIDOR FECHA CIF: "+linea);

		byte[] fechaCifrada = Logica.toByteArray(linea);

		byte[] fechaDescifrada = Logica.simetrico(fechaCifrada, llaveSimetrica, Logica.BLOWFISH, Cipher.DECRYPT_MODE);

		System.out.println(">> CLIENTE FECHA DESC: "+Logica.toHexString(fechaDescifrada));
		
		//15 RESPONDER OK OUT

		outWriter.println("OK");
		
		System.out.println(">> CLIENTE: OK");
		
		
	}	



}
