package cert;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi.EC;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.PSSSignatureSpi.SHA1withRSA;
import org.bouncycastle.jce.PKCS10CertificationRequest;

public class CertRequestGenerator {
	
	KeyPair       keyPair;
	X500Principal subjectName;
	SHA1withRSA sha1 = new SHA1withRSA();
	
	 
	public CertRequestGenerator(String name) {
		try {
			keyPair = EC.getInstance("RSA").generateKeyPair();
			subjectName = new X500Principal("CN="+name);
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}
	
	public PKCS10CertificationRequest generateRequests() {
	PKCS10CertificationRequest kpGen = null;
	try {
		kpGen = new PKCS10CertificationRequest(
								"SHA1withRSA",
								subjectName ,
					            keyPair.getPublic(),
					            null,
					            keyPair.getPrivate());
	} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException e) {
		e.printStackTrace();
	}
		return kpGen;
	}

}
