package cert;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi.EC;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.PSSSignatureSpi.SHA1withRSA;
import org.bouncycastle.x509.X509V1CertificateGenerator;

public class CertCreator {
	private KeyPair keyPair;
	private PrivateKey privateKey;
	private PublicKey publicKey;
	private SHA1withRSA sha1 = new SHA1withRSA();
	private X500Principal dnName;
	
	public CertCreator() {
		try {
			keyPair = EC.getInstance("RSA").generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		privateKey = keyPair.getPrivate();
		publicKey = keyPair.getPublic();

		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}
	
	public X509Certificate generateCert(String name) {
		
		Date startDate = new Date();             // time from which certificate is valid
		Calendar cal = Calendar.getInstance();
	    cal.setTime(startDate);
	    cal.add(Calendar.DATE, 7); 			//minus number would decrement the days
		Date expiryDate = cal.getTime();             // time after which certificate is not valid
		BigInteger serialNumber = new BigInteger("123456789");     // serial number for certificate
		X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
		dnName = new X500Principal("CN="+name);
		certGen.setSerialNumber(serialNumber);
		certGen.setIssuerDN(dnName);
		certGen.setNotBefore(startDate);
		certGen.setNotAfter(expiryDate);
		certGen.setSubjectDN(dnName);                       // note: same as issuer
		certGen.setPublicKey(keyPair.getPublic());
		certGen.setSignatureAlgorithm("SHA1withRSA");
		X509Certificate cert = null;
		try {
			cert = certGen.generate(keyPair.getPrivate(), "BC");
		} catch (CertificateEncodingException | InvalidKeyException | IllegalStateException | NoSuchProviderException
				| NoSuchAlgorithmException | SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return cert;
	}

	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	public void setPrivateKey(PrivateKey privateKey) {
		this.privateKey = privateKey;
	}

	public PublicKey getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(PublicKey publicKey) {
		this.publicKey = publicKey;
	}
	public String getName() {
		return dnName.getName();
	}
	
	

}
