
import java.io.FileInputStream;
import java.io.File;
import java.io.FileOutputStream;
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
import javax.crypto.spec.DESKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class DesempaquetarCompostela{
/* args[0] = paquete
 * args[1] = num albergues
 * args[2] = identificador albergue1
 * args[3] = clave pública albergue1
 * ...
 * args[N-3] = identificador albergueN
 * args[N-2] = clave pública albergueN
 * args[N-1] = clave pública peregirno
 * args[N] = clave privada oficina
 */		
	
	public static void main(String [] args) throws Exception{
		
		int numAlbergues = Integer.parseInt(args[1]);
		int contador = 0;
		int i=2;

/*----------------------Leer contenido paquete------------------------------*/
		Paquete paquete = PaqueteDAO.leerPaquete(args[0]);
		
/*----------------------Desencriptar clave aleatoria con clave privada oficina------------------------------*/		
		Bloque bloque = paquete.getBloque("PEREGRINO_CLAVE");
		byte[] peregrino_clave = bloque.getContenido();
		File file = new File(args[args.length-1]);
		int size = (int)file.length();
		byte[] buffer = new byte[size];
		FileInputStream in = new FileInputStream(file);
		in.read(buffer);
		in.close();
		
		Security.addProvider(new BouncyCastleProvider());
		PKCS8EncodedKeySpec clavePrivadaSpec = new PKCS8EncodedKeySpec(buffer);
		KeyFactory keyFactoryRSAoficina = KeyFactory.getInstance("RSA", "BC");
		PrivateKey clavePrivadaOficina = keyFactoryRSAoficina.generatePrivate(clavePrivadaSpec);
		
		Cipher cifrador = Cipher.getInstance("RSA","BC");
		cifrador.init(Cipher.DECRYPT_MODE, clavePrivadaOficina);
		byte[] bytes = cifrador.doFinal(peregrino_clave);
		
		DESKeySpec DESspec = new DESKeySpec(bytes);
		SecretKeyFactory secretKeyFactoryDES = SecretKeyFactory.getInstance("DES");
		SecretKey clave = secretKeyFactoryDES.generateSecret(DESspec);
		
/*---------------Desencriptar datos peregrino con clave aleatoria------------------------*/		
		bloque = paquete.getBloque("PEREGRINO_DATOS");
		byte[] peregrino_datos = bloque.getContenido();
		
		cifrador = Cipher.getInstance("DES/ECB/PKCS5Padding");
		cifrador.init(Cipher.DECRYPT_MODE, clave);
		bytes = cifrador.doFinal(peregrino_datos);
		String datosDesencriptados = new String(bytes);
		
/*-----------------------------Comprobar firma peregrino---------------------------------*/
		bloque = paquete.getBloque("PEREGRINO_FIRMA");
		byte[] peregrino_firma = bloque.getContenido();
		file = new File(args[args.length-2]);
		size = (int)file.length();
		buffer = new byte[size];
		in = new FileInputStream(file);
		in.read(buffer);
		in.close();
		
		Security.addProvider(new BouncyCastleProvider());
		X509EncodedKeySpec clavePublicaSpec = new X509EncodedKeySpec(buffer);
		KeyFactory keyFactoryRSAperegrino = KeyFactory.getInstance("RSA", "BC");
		PublicKey clavePublicaPeregrino = keyFactoryRSAperegrino.generatePublic(clavePublicaSpec);
		
		Signature firma = Signature.getInstance("SHA1withRSA","BC");
		firma.initVerify(clavePublicaPeregrino);
		firma.update(bytes);
		
		if (firma.verify(peregrino_firma)) {
			System.out.println("Datos peregrino:\n"+datosDesencriptados);
		}
		else {
			System.out.println ("Los datos del peregrino han sido manipulados");
		}
		
		
/*----------------------------Desencriptar albergues-----------------------*/
		while(contador<numAlbergues){
			
			//Desencriptar clave aleatoria con clave privada de oficina
			bloque = paquete.getBloque(args[i]+"_CLAVE");
			byte[] albergue_clave = bloque.getContenido();
			cifrador = Cipher.getInstance("RSA","BC");
			cifrador.init(Cipher.DECRYPT_MODE, clavePrivadaOficina);
			bytes = cifrador.doFinal(albergue_clave);
			DESspec = new DESKeySpec(bytes);
			secretKeyFactoryDES = SecretKeyFactory.getInstance("DES");
			clave = secretKeyFactoryDES.generateSecret(DESspec);
			
			//Desencriptar datos albergue con clave aleatoria
			bloque = paquete.getBloque(args[i]+"_DATOS");
			byte[] albergue_datos = bloque.getContenido();
			cifrador = Cipher.getInstance("DES/ECB/PKCS5Padding");
			cifrador.init(Cipher.DECRYPT_MODE, clave);
			bytes = cifrador.doFinal(albergue_datos);
			datosDesencriptados = new String(bytes);
			
			//Comprobar firma albergue
			bloque = paquete.getBloque(args[i]+"_FIRMA");
			byte[] albergue_firma = bloque.getContenido();
			file = new File(args[i+1]);
			size = (int)file.length();
			buffer = new byte[size];
			in = new FileInputStream(file);
			in.read(buffer);
			in.close();
			
			Security.addProvider(new BouncyCastleProvider());
			clavePublicaSpec = new X509EncodedKeySpec(buffer);
			KeyFactory keyFactoryRSAalbergue = KeyFactory.getInstance("RSA", "BC");
			PublicKey clavePublicaAlbergue = keyFactoryRSAalbergue.generatePublic(clavePublicaSpec);
			
			firma = Signature.getInstance("SHA1withRSA","BC");
			firma.initVerify(clavePublicaAlbergue);
			byte[] sello = new byte[bytes.length + peregrino_firma.length];
			System.arraycopy(bytes, 0, sello, 0, bytes.length);
			System.arraycopy(peregrino_firma, 0, sello, bytes.length, peregrino_firma.length);
			firma.update(sello);
			
			if (firma.verify(albergue_firma)) {
				System.out.println("Datos "+args[i]+":\n"+datosDesencriptados);
			}
			else {
				System.out.println ("Los datos del "+args[i]+" han sido manipulados");
			}
			
			contador++;
			i=i+2;
		}
		
	}
}
