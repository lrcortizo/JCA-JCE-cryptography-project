
import java.io.File;
import java.io.FileInputStream;
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

public class SellarCompostela {
	public static void main(String [] args)throws Exception{
		
/* args[0] = paquete
 * args[1] = identificador albergue
 * args[2] = clave publica oficina
 * args[3] = clave privada albergue
 */		
		
		Map<String, String> datos = new HashMap<String, String>();
		String nombre;
		String fCreacion;
		String lugar;
		String incidencias;
		
/*----------------Pedir datos por teclado-------------------------------*/
		Scanner sc = new Scanner (System.in);
		
		System.out.println("Introduzca su nombre:");
		nombre = sc.nextLine();
		datos.put("nombre", nombre);
		
		System.out.println("Introduzca la fecha de hoy:");
		fCreacion = sc.nextLine();
		datos.put("fecha", fCreacion);
		
		System.out.println("Introduzca su localizacion:");
		lugar = sc.nextLine();
		datos.put("lugar", lugar);
		
		System.out.println("Incidencias:");
		incidencias = sc.nextLine();
		datos.put("incidencias", incidencias);
		
		sc.close();
		String json = JSONUtils.map2json(datos);
		
/*-----------------------Cifrar datos con clave aleatoria----------------------*/	
		KeyGenerator generadorDES = KeyGenerator.getInstance("DES");
		generadorDES.init(56);
		SecretKey clave = generadorDES.generateKey();
		
		Cipher cifrador = Cipher.getInstance("DES/ECB/PKCS5Padding");
		cifrador.init(Cipher.ENCRYPT_MODE, clave);
		byte [] bytes = cifrador.doFinal(json.getBytes("UTF-8"));
		
		Bloque bloque = new Bloque(args[1]+"_DATOS", bytes);
		Paquete paquete = PaqueteDAO.leerPaquete(args[0]);
		paquete.anadirBloque(bloque);
		
/*-----------------Crifrar clave aleatoria con clave pública oficina---------------*/
		File file = new File(args[2]);
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
		
		bloque = new Bloque(args[1]+"_CLAVE", bytes);
		paquete.anadirBloque(bloque);
		
/*-----------------------------------Sello albergue---------------------------------*/
		bloque = paquete.getBloque("PEREGRINO_FIRMA");
		byte[] peregrino_firma = bloque.getContenido();
		
		file = new File(args[3]);
		size = (int)file.length();
		buffer = new byte[size];
		in = new FileInputStream(file);
		in.read(buffer);
		in.close();
		
		PKCS8EncodedKeySpec clavePrivadaSpec = new PKCS8EncodedKeySpec(buffer);
		KeyFactory keyFactoryRSAalbergue = KeyFactory.getInstance("RSA", "BC");
		PrivateKey clavePrivadaAlbergue = keyFactoryRSAalbergue.generatePrivate(clavePrivadaSpec);

		Signature firma = Signature.getInstance("SHA1withRSA","BC");
		firma.initSign(clavePrivadaAlbergue);
		byte[] sello = new byte[json.getBytes().length + peregrino_firma.length];
		System.arraycopy(json.getBytes(), 0, sello, 0, json.getBytes().length);
		System.arraycopy(peregrino_firma, 0, sello, json.getBytes().length, peregrino_firma.length);
		firma.update(sello);
		bytes = firma.sign();
		
		bloque = new Bloque(args[1]+"_FIRMA", bytes);
		paquete.anadirBloque(bloque);
		
/*--------------------------------Escribir paquete--------------------------------------*/
		PaqueteDAO.escribirPaquete("./Compostela.bin", paquete);
	}
}
