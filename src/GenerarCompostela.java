
import java.io.FileInputStream;
import java.io.File;
import java.nio.charset.Charset;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import javax.crypto.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;



public class GenerarCompostela {
	public static void main(String[] args) throws Exception {
		
/* args[0] = nombre del paquete
 * args[1] = clave publica oficina
 * args[2] = clave privada peregrino
 */		
		Map<String, String> datos = new HashMap<String, String>();
		String nombre;
		String dni;
		String domicilio;
		String fCreacion;
		String lugar;
		String motivaciones;
		
/*----------------Pedir datos por teclado-------------------------------*/
		Scanner sc = new Scanner (System.in);
		
		System.out.println("Introduzca su nombre:");
		nombre = sc.nextLine();
		datos.put("nombre", nombre);
		
		System.out.println("Introduzca su DNI:");
		dni = sc.nextLine();
		datos.put("DNI", dni);
		
		System.out.println("Introduzca su domicilio:");
		domicilio = sc.nextLine();
		datos.put("domicilio", domicilio);
		
		System.out.println("Introduzca la fecha de hoy:");
		fCreacion = sc.nextLine();
		datos.put("fecha", fCreacion);
		
		System.out.println("Introduzca su localizacion actual:");
		lugar = sc.nextLine();
		datos.put("lugar", lugar);
		
		System.out.println("Introduzca sus motivaciones del peregrinaje:");
		motivaciones = sc.nextLine();
		datos.put("motivaciones", motivaciones);
	
		sc.close();
		String json = JSONUtils.map2json(datos);
/*-----------------------Cifrar datos con clave aleatoria----------------------*/	
		KeyGenerator generadorDES = KeyGenerator.getInstance("DES");
		generadorDES.init(56);
		SecretKey clave = generadorDES.generateKey();
		Cipher cifrador = Cipher.getInstance("DES/ECB/PKCS5Padding");
		cifrador.init(Cipher.ENCRYPT_MODE, clave);
		byte[] bytes = cifrador.doFinal(json.getBytes("UTF-8"));
		
		Bloque bloque = new Bloque("PEREGRINO_DATOS", bytes);
		
		Paquete paquete = new Paquete();
		paquete.anadirBloque(bloque);

/*----------Crifrar clave aleatoria con clave pública oficina------------*/
		File file = new File(args[1]);
		FileInputStream in = new FileInputStream(file);
		int size = (int)file.length();
		byte [] buffer = new byte[size];
		in.read(buffer);
		in.close();
		
		Security.addProvider(new BouncyCastleProvider());
		X509EncodedKeySpec clavePublicaSpec = new X509EncodedKeySpec(buffer);
		KeyFactory keyFactoryRSAoficina = KeyFactory.getInstance("RSA", "BC");
		PublicKey clavePublicaOficina = keyFactoryRSAoficina.generatePublic(clavePublicaSpec);
		
		cifrador = Cipher.getInstance("RSA","BC");
		cifrador.init(Cipher.ENCRYPT_MODE, clavePublicaOficina);
		bytes = cifrador.doFinal(clave.getEncoded());
		
		bloque = new Bloque("PEREGRINO_CLAVE", bytes);
		paquete.anadirBloque(bloque);

/*--------------------Firma digital peregrino------------------------*/
		file = new File(args[2]);
		size = (int)file.length();
		buffer = new byte[size];
		in = new FileInputStream(file);
		in.read(buffer);
		in.close();
		
		PKCS8EncodedKeySpec clavePrivadaSpec = new PKCS8EncodedKeySpec(buffer);
		KeyFactory keyFactoryRSAperegrino = KeyFactory.getInstance("RSA", "BC");
		PrivateKey clavePrivadaPeregrino = keyFactoryRSAperegrino.generatePrivate(clavePrivadaSpec);
		

		Signature firma = Signature.getInstance("SHA1withRSA","BC");
		firma.initSign(clavePrivadaPeregrino);
		bytes = json.getBytes("UTF-8");
		firma.update(bytes);
		bytes = firma.sign();
		
		bloque = new Bloque("PEREGRINO_FIRMA", bytes);
		paquete.anadirBloque(bloque);

/*--------------------------------Escribir paquete--------------------------------------*/
		PaqueteDAO.escribirPaquete(args[0], paquete);
		
	}
}
