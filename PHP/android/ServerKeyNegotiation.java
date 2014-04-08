import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
public class ServerKeyNegotiation{
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
	static char low4bit2char(int i)
	{
		int target = i&0xF;
		if(target >=0 && target <=9)
			return (char)(target + '0');
		else
			return (char)(target - 10 +'A');
	}
	static String b2s(byte[] b)
	{
		String s="";
		for(int i=0; i<b.length; i++)
		{
			s+=low4bit2char(b[i]>>4 & 0xF);
			s+=low4bit2char(b[i] & 0xF);
		}
		return s;
	}
	public static void main(String [] args)
	{
		try{
			//get DH clientPublicKey string
			String clientPubKeyStr = args[args.length-1];
			//get DH clientPublicKey byte array
			byte[] clientPubKeyByte = s2b(clientPubKeyStr);
			//rebuild DH clientPublicKey
			KeyFactory serverKeyFac = KeyFactory.getInstance("DH");
			PublicKey clientPubKey = serverKeyFac.generatePublic(new X509EncodedKeySpec(clientPubKeyByte));
			//read clientPublicKey and generate server's DH key pair (same as client's)
			DHParameterSpec dhParamSpec = ((DHPublicKey)clientPubKey).getParams();
			KeyPairGenerator serverKpairGen = KeyPairGenerator.getInstance("DH");
			serverKpairGen.initialize(dhParamSpec);
			KeyPair serverKpair = serverKpairGen.generateKeyPair();
			//initialize DH serverPrivateKey
			KeyAgreement serverKeyAgree = KeyAgreement.getInstance("DH");
			serverKeyAgree.init(serverKpair.getPrivate());
			//generate server's Negotiation Private Key
			serverKeyAgree.doPhase(clientPubKey, true);
			SecretKey serverDesKey = serverKeyAgree.generateSecret("DES");
			//output DH serverPublicKey string
			byte[] serverPubKeyByte = serverKpair.getPublic().getEncoded();
			System.out.println(b2s(serverPubKeyByte));
		}
		catch(Exception e)
		{}
	}
}
