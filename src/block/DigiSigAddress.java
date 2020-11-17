package block;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Formatter;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bitcoin.Base58;
import org.json.JSONException;
import org.json.JSONObject;
import org.ripemd160.Ripemd160;

public class DigiSigAddress {

    private static final String SPEC = "secp256k1";
    private static final String ALGO = "SHA256withECDSA";
	public PrivateKey privateKey;
	public PublicKey publicKey;
	
    private JSONObject sender() 
    		throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, 
    		UnsupportedEncodingException, SignatureException, JSONException, NoSuchProviderException {

    	
    	
    	
    	/* 
    	 * 1. ECDSA 기반 key pair (private, public key) 생성 
    	 * 
    	 * */
   
        ECGenParameterSpec ecSpec = new ECGenParameterSpec(SPEC);
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(ecSpec, new SecureRandom());
        KeyPair keypair = g.generateKeyPair();
        publicKey = keypair.getPublic();
        privateKey = keypair.getPrivate();
    

		System.out.println("공개키: "+bytesToHex(publicKey.getEncoded()));
		System.out.println("개인키: "+bytesToHex(privateKey.getEncoded()));
 
        
		
		

        /* 
         * 
         * 2. 비트코인의 주소 체계와 같은 주소 생성
         * 
         */
		
		ECPublicKey epub = (ECPublicKey) publicKey;
		ECPoint pt = epub.getW();
		byte[] bcPub = new byte[33];
		bcPub[0] = 2;
		System.arraycopy(pt.getAffineX().toByteArray(), 0, bcPub, 1, 32);
		
		MessageDigest sha = MessageDigest.getInstance("SHA-256");
		byte[] s1 = sha.digest(bcPub);
		
		byte[] ripeMD = Ripemd160.getHash(s1);
		
		//add 0x00
		byte[] ripeMDPadded = new byte[ripeMD.length + 1];
		ripeMDPadded[0] = 0;
		
		System.arraycopy(ripeMD, 0, ripeMDPadded, 1, 1);
		
		byte[] shaFinal = sha.digest(sha.digest(ripeMDPadded));
		
		//append ripeMDPadded + shaFinal = sumBytes
		byte[] sumBytes = new byte[25];
		System.arraycopy(ripeMDPadded, 0, sumBytes, 0, 21);
		System.arraycopy(shaFinal, 0, sumBytes, 21, 4);
		
		//base 58 encode
		
		System.out.println("Bitcoin Address: " + Base58.encode(sumBytes));      
        //비트코인 주소 end
        
        /*
         * 3. 임의의 데이터(문자열)을 private key로 signature 생성,
         * 임의 데이터 사용자가 직접 입력 
         *  
         */
		
		
		
		
		Scanner sc = new Scanner(System.in);
		System.out.println("서명내용을 입력하세요");
		String plaintext = sc.next();
		
        //String plaintext = "Hello";

		
        // 사인
        Signature ecdsaSign = Signature.getInstance(ALGO);
        ecdsaSign.initSign(privateKey);
        ecdsaSign.update(plaintext.getBytes("UTF-8"));
        byte[] signature = ecdsaSign.sign();
        String pub = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        String sig = Base64.getEncoder().encodeToString(signature);

		//System.out.println("sig: "+sig);
		//System.out.println("pub: "+pub);
		
		
        JSONObject obj = new JSONObject();
        
        obj.put("publicKey", pub);
        obj.put("signature", sig);
        obj.put("message", plaintext);
        obj.put("algorithm", ALGO);
        
		System.out.println("json data: "+obj);
		
		
        return obj;
    }

    
    public boolean receiver(JSONObject obj) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, UnsupportedEncodingException, SignatureException, JSONException {

    	
        /*
         * 
         * 4. Public key를 이용하여 검증
         * 
         * 
         */
    	
    	
    	
        Signature ecdsaVerify = Signature.getInstance(obj.getString("algorithm"));
        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(obj.getString("publicKey")));

        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

        ecdsaVerify.initVerify(publicKey);
        ecdsaVerify.update(obj.getString("message").getBytes("UTF-8"));
        boolean result = ecdsaVerify.verify(Base64.getDecoder().decode(obj.getString("signature")));

        return result;
    }
    
    
	public static String bytesToHex(byte[] bytes) {
	    StringBuilder sb = new StringBuilder(bytes.length * 2);
	    @SuppressWarnings("resource")
		Formatter formatter = new Formatter(sb);
	    for (byte b : bytes) {
	        formatter.format("%02x", b);
	    }
	    return sb.toString();
	}
	
     public static void main(String[] args) throws JSONException, NoSuchProviderException{
        try {
            DigiSigAddress digiSig = new DigiSigAddress();
            JSONObject obj = digiSig.sender();

            
            
            
            
            /*
             * 
             * 검증결과 출력
             * 
             * 
             */
            
            
            System.out.println("디지털사인 데이터:" + obj);
            boolean result = digiSig.receiver(obj);
            System.out.println("서명 데이터 확인 :" + result);
            
            
            
            
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(DigiSigAddress.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidAlgorithmParameterException ex) {
            Logger.getLogger(DigiSigAddress.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(DigiSigAddress.class.getName()).log(Level.SEVERE, null, ex);
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(DigiSigAddress.class.getName()).log(Level.SEVERE, null, ex);
        } catch (SignatureException ex) {
            Logger.getLogger(DigiSigAddress.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeySpecException ex) {
            Logger.getLogger(DigiSigAddress.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

}
