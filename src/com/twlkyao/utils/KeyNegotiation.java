package com.twlkyao.utils;

import android.annotation.SuppressLint;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.protocol.HTTP;
import org.apache.http.util.EntityUtils;
import org.json.JSONException;
import org.json.JSONObject;


public class KeyNegotiation {
	public static char low4bit2char(int i)
	{
		int target = i&0xF;
		if(target >=0 && target <= 9)
			return (char)(target + '0');
		else
			return (char)(target - 10 + 'A');
	}
	public static String b2s(byte [] b)
	{
		String s="";
		for(int i=0; i< b.length; i++)
		{
			s+=low4bit2char(b[i]>>4 & 0xF);
			s+=low4bit2char(b[i]&0xF);
		}
		return s;
	} 
	static int c2i(char ch)    
    {                          
            if(ch>='0'&&ch<='9')
                    return ch-'0';
            else if(ch>='A'&&ch<='F')
                    return ch-'A'+10;
            else if(ch>='a'&&ch<='f')    
                    return ch-'a'+10;    
            else               
                    return -1; 
    }                          
    static byte[] s2b(String str)
    {                          
            byte[] result = new byte[str.length()/2];
            for(int i=0,j=0;i<result.length;i++,j+=2)
            {                  
                    result[i] = (byte)((c2i(str.charAt(j))<<4) + c2i(str.charAt(j+1)));
            }                  
            return result;     
    } 

    private static String negotiationUrl = ConstantVariables.BASE_URL + ConstantVariables.NEGOTIATION_URL;
    private static String sessionid = "";
    /**
	 * Get the server's DH public key. 
	 * @param clientDHPublicKey The DH public key of the client
	 * @param negotiationUrl The url for negotiating with server
	 * @return The The DH public key of the server
	 */
	static JSONObject GenSessionKeyOnServer_ReturnServerDHPublicKeyAndSessionID (String clientDHPublicKey, String negotiationUrl, String encryptAlgorithm) {
		
		HttpPost httpRequest = new HttpPost(negotiationUrl); // construct a new HttpPost instance according to the uri
		
		// use name-value pair to store the parameters to pass
		List<BasicNameValuePair> params=new ArrayList<BasicNameValuePair>();
		params.add(new BasicNameValuePair("clientDHPublicKey", clientDHPublicKey)); // add the clientDHPublicKey name-value
		params.add(new BasicNameValuePair("encryptAlgorithm", encryptAlgorithm)); // add the encryptAlgorithm name-value
		
		try{	
			// encode the entity with utf8, and send the entity to the request
			httpRequest.setEntity(new UrlEncodedFormEntity(params,HTTP.UTF_8)); 
		} catch (UnsupportedEncodingException e){
			e.printStackTrace();
		}
		try{
			// execute an HTTP request and ge the result
			HttpResponse httpResponse = new DefaultHttpClient().execute(httpRequest); // execute the http request
			// response status is ok
			if(httpResponse.getStatusLine().getStatusCode() == HttpStatus.SC_OK){	
				// get the response string and parse it
				HttpEntity entity = httpResponse.getEntity(); // obtain the HTTP response entity
				if (entity != null) { 
					String info =  EntityUtils.toString(entity); // convert the entity to string
					JSONObject jsonObject;
					try {
						jsonObject = new JSONObject(info); // construct an JsonObject instance from the name-value Json string		
						return jsonObject;
					} catch (JSONException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				} // status code equal ok 
			}
		} catch (ClientProtocolException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
    
	@SuppressLint("TrulyRandom")
	public static HashMap<String, String> negotiation(String encryptAlgorithm)
	{
		try
		{
			//generate DH key pair
			KeyPairGenerator clientKpairGen = KeyPairGenerator.getInstance("DH");
			clientKpairGen.initialize(512);
			KeyPair clientKpair = clientKpairGen.generateKeyPair(); // a long time
			//generate DH clientPublicKey byte array
			byte[] clientPubKeyByte = clientKpair.getPublic().getEncoded();
			//generate DH clientPublicKey string
			String clientPubKeyStr = b2s(clientPubKeyByte);		
			//get DH serverPublicKey string
			JSONObject serverPubKeyStr_sessionIDStr = GenSessionKeyOnServer_ReturnServerDHPublicKeyAndSessionID(clientPubKeyStr,negotiationUrl,encryptAlgorithm);
			//get DH serverPublicKey byte array
			sessionid = serverPubKeyStr_sessionIDStr.getString("sessionid");
			String serverPubKeyStr = serverPubKeyStr_sessionIDStr.getString("serverPubKey");
			byte[] serverPubKeyByte = s2b(serverPubKeyStr);
			//rebuild DH serverPublicKey
			KeyFactory clientKeyFac = KeyFactory.getInstance("DH");
			PublicKey serverPubKey = clientKeyFac.generatePublic(new X509EncodedKeySpec(serverPubKeyByte));
			//initialize DH clientPrivateKey
			KeyAgreement clientKeyAgree = KeyAgreement.getInstance("DH");
			clientKeyAgree.init(clientKpair.getPrivate());
			//generate client's Negotiation Private Key
			clientKeyAgree.doPhase(serverPubKey, true);
			//generate client's Session Key
			SecretKey clientConversationKey = clientKeyAgree.generateSecret(encryptAlgorithm);
			HashMap<String, String> session =new HashMap<String, String>();
			session.put("sessionid", sessionid);
			session.put("conversationKey", b2s(clientConversationKey.getEncoded()));
			return session;
		}
		catch(Exception e)
		{
			e.printStackTrace();
		}
		return null;
	}
}
