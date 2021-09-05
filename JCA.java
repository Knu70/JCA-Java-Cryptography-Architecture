package road2root.com.jca;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.InputMismatchException;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/*
 * @author road2root
 */
public class JCA {

    /**
     * @param args the command line arguments
     */
    //VARIABLES
        static String fichero, password, datos, textoPlano;
        static char[] passwordCharA;
        static byte[] salt = new byte[8];
        static byte [] clavePrivadaCifrada,documento,publica,privada,firma,datosDeFirma,datosDocumento,textoCifradoByte,claveSimetricaCifradaConClavePublica,data1,claveCifradaConPublica,claveDescifrada,textoDocumento;
        static int op;
        static BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        static FileOutputStream fos = null;
        static FileInputStream fis = null;
        
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, SignatureException {
        
        Security.insertProviderAt(new org.bouncycastle.jce.provider.BouncyCastleProvider(), 1);

        Scanner sn = new Scanner(System.in);
        boolean salir = false;
        int opcion; //Guarda la opcion del usuario
 
        while (salir == false) {
 
            System.out.println("1. Generar y almacenar el par de claves");
            System.out.println("2. Firmar digitalmente un fichero");
            System.out.println("3. Verificar firma digital de un fichero");
            System.out.println("4. Cifrar y descifrar un fichero");
            System.out.println("5. Salir.");
 
            try {
 
                System.out.println("Escribe una de las opciones");
                opcion = sn.nextInt();
 
                switch (opcion) {
                    case 1:
                        generarAlmacenarParClaves();
                        break;
                    case 2:
                        firmarDigitalmenteFichero();
                        break;
                    case 3:
                        verificarFirmaDigitalDeFichero();
                        break;
                    case 4:
                        cifrarDescifrarFichero();
                        break;
                    case 5:
                        salir = true;
                        break;
                    default:
                        System.out.println("Solo números entre 1 y 5");
                }
            } catch (InputMismatchException e) {
                System.out.println("Debes insertar un número");
                sn.next();
            }
        }
    }

//OPCION 1: GENERAR Y ALMACENAR EL PAR DE CLAVES
    static void generarAlmacenarParClaves() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
        
        System.out.println("");
        
        //GENERO Y ALMACENAR EL PAR DE CLAVES
        KeyPairGenerator kg = KeyPairGenerator.getInstance("RSA");
        kg.initialize(2048);
        KeyPair kp = kg.generateKeyPair();

        //OBTENGO CLAVE PUBLICA Y PRIVADA 
        PublicKey kpu = kp.getPublic();
        PrivateKey kpr = kp.getPrivate();

        //CONVIERTO LAS CLAVES EN BYTES PARA GUARDAR EN FICHERO
        publica = kpu.getEncoded();
        privada = kpr.getEncoded();
        
        //GUARDO LA CLAVE PUBLICA EN UN FICHERO EXTERNO  
        System.out.println("Introduce nombre del fichero donde guardar la clave publica: ");
        fichero = br.readLine();
        almacenarEnFichero(fichero, publica);
	    
        //ENCRIPTO CLAVE PRIVADA CON PASSWORD Y SALT (PBE) 
        System.out.println("\nIntroduce el password para cifrar la clave privada: ");
        password = br.readLine();
        passwordCharA = password.toCharArray();

        //CREO UN SALT Y GENERO SECRETKEY
        SecureRandom scr = SecureRandom.getInstance("SHA1PRNG");
        scr.nextBytes(salt);
        SecretKey clave = generarClave(passwordCharA, salt);

        //CIFRO CLAVE PRIVADA CON LA CLAVE QUE CONTIENE EL SALT Y EL PASSWORD
        clavePrivadaCifrada = cifrarClave(privada,clave);

        //GUARDO LA CLAVE EN UN FICHERO EXTERNO  
        System.out.println("Introduce nombre de fichero donde guardar la clave privada: ");
        fichero = br.readLine();
        almacenarEnFicheroClavePrivada(fichero, clavePrivadaCifrada,salt);
    }

//OPCION 2: FIRMAR DIGITALMENTE UN FICHERO
    static void firmarDigitalmenteFichero() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, SignatureException {
        
        System.out.println("");
        
        //SOLICITO EL TEXTO QUE QUIERO FIRMAR
        System.out.println("Introduce nombre del fichero donde guardar documento que queremos firmar: ");
        fichero = br.readLine();
        System.out.println("Texto del fichero a firmar: ");
        datos = br.readLine();
        documento = datos.getBytes();
        almacenarEnFichero(fichero, documento);

        //CLAVE PRIVADA, INVIERTO LA CONVERSION ENCODE Y PREPARO PARA FIRMAR 
        PKCS8EncodedKeySpec priv = new PKCS8EncodedKeySpec(descifrar());
        KeyFactory kfPrivada = KeyFactory.getInstance("RSA");
        PrivateKey pk = kfPrivada.generatePrivate(priv);

        //CREO OBJETO DE FIRMA Y LO INICIALIZO CON LA CLAVE PRIVADA 
        Signature firmaPrivada = Signature.getInstance("RSA");
        firmaPrivada.initSign(pk);
        firmaPrivada.update(documento);
        
        //CREO LA FIRMA
        datosDeFirma=firmaPrivada.sign();
        System.out.println("Documento firmado con clave privada!!!");	

        //ALMACENO LA FIRMA EN UN FICHERO
        System.out.println("Introduce nombre del fichero donde guardar la firma: ");
        fichero = br.readLine();
        almacenarEnFichero(fichero, datosDeFirma);
    }
    
//OPCION 3: VERIFICAR FIRMA DIGITAL DE UN FICHERO
    static void verificarFirmaDigitalDeFichero() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        
        System.out.println("");
        
        //RECUPERO CLAVE PUBLICA
        System.out.println("Introduce nombre del fichero que contiene la clave publica: ");
        fichero = br.readLine();

        //INVIERTO LA CONVERSION ENCODE Y PREPARO PARA VERIFICAR 
        X509EncodedKeySpec publ = new X509EncodedKeySpec(recuperarClavePPD(fichero));
        KeyFactory kfPublico = KeyFactory.getInstance("RSA");
        PublicKey publickey = kfPublico.generatePublic(publ);

        //RECUPERO FIRMA
        System.out.println("Introduce nombre del fichero que contiene la firma: ");
        fichero = br.readLine();
        firma = recuperarClavePPD(fichero);

        //RECUPERO DATOS DEL DOCUEMENTO
        System.out.println("Introduce nombre del fichero que contiene el documento: ");
        fichero = br.readLine();
        datosDocumento = recuperarClavePPD(fichero);

        //CREO OBJETO DE FIRMA Y LO INICIALIZO CON LA CLAVE PUBLICA LE PASO DATOS DEL DOCUMENTO
        Signature firmaPublica=Signature.getInstance("RSA");
        firmaPublica.initVerify(publickey);
        firmaPublica.update(datosDocumento);

        //VERIFICO FIRMA CON CLAVE PUBLICA
        if (firmaPublica.verify(firma) == true)
                System.out.println("Firma verificada!!!");
        else
                System.out.println("Firma no valida");

        //MUESTRO LOS DATOS GUARDADOS EN EL FICHERO
        mostrarDatos(datosDocumento);
    }

//OPCION 4: CIFRAR Y DESCIFRAR UN FICHERO
    static void cifrarDescifrarFichero() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
        
        System.out.println("");
        
        //CREO CLAVE DE SESION (CLAVE SIMETRICA)
        KeyGenerator kg1 = KeyGenerator.getInstance("DES");
        kg1.init(56);
        SecretKey claveSimetrica = kg1.generateKey();
        Cipher cifrador = Cipher.getInstance("DES");
        cifrador.init(Cipher.ENCRYPT_MODE, claveSimetrica);

        //ENCRIPTO Y GUARDO TEXTO ENCRIPTADO EN FICHERO 
        System.out.println("\nIntroduce nombre de fichero donde quieres guardar los datos? ");
        fichero = br.readLine();
        try {
            fos = new FileOutputStream(fichero+".txt");
            	 	
            System.out.println("Introduce la informacion que a cifrar: ");
            textoPlano = br.readLine();

            //ENCRIPTO CADENA
            textoCifradoByte = cifrador.doFinal(textoPlano.getBytes("UTF-8"));

             //ESCRIBO CADENA CIFRADA EN FICHERO
             fos.write(textoCifradoByte); 
           
        }catch (IOException e){
            System.out.println(e);
        }
        finally{
            if(fos!=null){
                try{
                    fos.close();
                }catch(IOException ex){
                }
            }
        }

        //RECUPERO CLAVE PUBLICA
        System.out.println("Introduce nombre del fichero que contiene la clave publica: ");
        fichero = br.readLine();

        //INVIERTO LA CONVERSION ENCODE
        X509EncodedKeySpec clavepublica = new X509EncodedKeySpec(recuperarClavePPD(fichero));
        KeyFactory keyFactoryPublico1 = KeyFactory.getInstance("RSA");
        PublicKey publickey1 = keyFactoryPublico1.generatePublic(clavepublica);

        //CIFRO LA CLAVE SIMETRICA(DE SESION) CON LA CLAVE(ASIMETRICA) PUBLICA PARA PODER TRANSPORTARLA
        Cipher ci = Cipher.getInstance("RSA");
        ci.init(Cipher.ENCRYPT_MODE,publickey1);
        claveSimetricaCifradaConClavePublica = ci.doFinal(claveSimetrica.getEncoded());

        //GUARDO CLAVE SIMETRICA CIFRADA CON CLAVE PUBLICA EN FICHERO
        System.out.println("Nombre del fichero para guardar la clave simetrica cifrada con clave publica: ");
        fichero = br.readLine();
        almacenarEnFichero(fichero, claveSimetricaCifradaConClavePublica);

        //LEO FICHERO CON DATOS ENCRIPTADOS    
        System.out.println("Nombre del fichero donde guardaste los datos cifrados con clave simetrica: ");
        fichero = br.readLine();
        data1=null;
        try{
            fis = new FileInputStream(fichero+".txt");
            data1 = new byte[fis.available()];
            fis.read(data1);   
        }catch (Exception e) {
            e.printStackTrace();
        }  
        finally{
            if(fis!=null){
                try{
                    fis.close();
                }catch(IOException ex){
                }
            }
        }

        //RECUPERO CLAVE PRIVADA 
        PKCS8EncodedKeySpec claveprivada=new PKCS8EncodedKeySpec(descifrar());
        KeyFactory kfPrivada1 = KeyFactory.getInstance("RSA");
        PrivateKey privatekey1 = kfPrivada1.generatePrivate(claveprivada);

        //LEO FICHERO QUE CONTIENE LA CLAVE SIMETRICA ENCRIPTADA CON CLAVE PUBLICA    
        System.out.println("Introduce nombre del fichero que contiene clave simetrica: ");
        fichero = br.readLine();
        claveCifradaConPublica = recuperarClavePPD(fichero);

        //DESENCRIPTO CLAVE SIMETRICA CON CLAVE PRIVADA
        ci.init(Cipher.DECRYPT_MODE,privatekey1);
        claveDescifrada=ci.doFinal(claveCifradaConPublica);

        //UTILIZO SECRETKEYSPEC PARA INVERTIR LA CONVERSION ENCODED Y LE PASO EL TIPO DE ALGORITMO
        SecretKey claveSimefinal = new SecretKeySpec(claveDescifrada,"DES");

        //DESENCRIPTO DATOS DE FICHERO
        cifrador.init(Cipher.DECRYPT_MODE,claveSimefinal);
        textoDocumento = cifrador.doFinal(data1);
        System.out.println(new String(textoDocumento));	
    }

    
    
//FUNCIONES DE CIFRADO, DESCIFRADO, GESTIÓN DE FIRMA Y CLAVE PUBLICA
    
    //ALMACENO EN FICHEROS
    static void almacenarEnFichero(String file, byte[] datos) throws IOException{
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(datos);
        }
    }

    //GUARDO CLAVE PRIVADA EN FICHERO
    static void almacenarEnFicheroClavePrivada(String file, byte[] privada, byte[] salt) throws IOException{
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(salt);
            fos.write(privada);
        }
    }

    //GENERO CLAVE QUE CIFRA LA CLAVE PRIVADA (PBE)
    static SecretKey generarClave(char[] pass, byte[] salt) throws InvalidKeySpecException, NoSuchAlgorithmException{
        PBEKeySpec pks = new PBEKeySpec(pass, salt, 10);                  
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
        SecretKey clave = skf.generateSecret(pks);
        return clave;
    }

    //CIFRO LA CLAVE PRIVADA
    static byte[] cifrarClave(byte[] clavePrivada, SecretKey k) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException{
        Cipher cifrador = Cipher.getInstance("PBEWithMD5AndDES");
        cifrador.init(Cipher.ENCRYPT_MODE, k);                          
        return cifrador.doFinal(clavePrivada);                        
    }


    //LEO LA CLAVE PRIVADA CIFRADA ALMACENADA EN EL FICHERO Y LA RETORNO
    static byte[] leerFichero(String file, byte[] salt) throws IOException{
        FileInputStream fis = new FileInputStream(file);
        fis.read(salt, 0, 8);                                      
        int dato = 0;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        while ((dato=fis.read())!=-1){
            baos.write(dato);
        }
        return baos.toByteArray();                                   
    }

    //DESCIFRO CLAVE PRIVADA (LE PASO LA CLAVE PRIVADA CIFRADA Y LA CLAVE CON LA QUE SE CIFRO)
    static byte[] descifrarClavePrivada(byte[] clavePrivadaCifrada, SecretKey k) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
        Cipher cifrador = Cipher.getInstance("PBEWithMD5AndDES");
        cifrador.init(Cipher.DECRYPT_MODE, k);
        return cifrador.doFinal(clavePrivadaCifrada);
    }		

    static byte[] descifrar() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException{
        String password, file;
        char[] passwordCharA;
        byte[] salt = new byte[8];
        byte[] clavePrivadaCifrada;
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));

        System.out.println("\nIntroduce el password para descifrar la clave privada: ");
        password = br.readLine();
        passwordCharA = password.toCharArray();

        System.out.println("\nIntroduce el nombre del fichero donde se encuentra la clave privada");
        file = br.readLine();
        clavePrivadaCifrada = leerFichero(file,salt);
        SecretKey clave = generarClave(passwordCharA, salt);
        byte[] clavePrivadaDescifrada = descifrarClavePrivada(clavePrivadaCifrada, clave);

        System.out.println("");
        System.out.println("\nClave Privada Descifrada! ");	
        return clavePrivadaDescifrada;
    }


    //METODO PARA RECUPERAR CLAVE PUBLICA, CLAVE PRIVADA Y DATOS DEL DOCUEMENTO
    static byte[] recuperarClavePPD(String file) throws IOException{
        FileInputStream fis = new FileInputStream(file);                                      
        int dato=0;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        while ((dato=fis.read())!=-1){
            baos.write(dato);
        }
        return baos.toByteArray();                                   
    }

    //METODO PARA MOSTRAR DATOS DEL DOCUMENTO
    public static void mostrarDatos(byte [] datos) {
        System.out.write(datos, 0, datos.length);
    } 

}
