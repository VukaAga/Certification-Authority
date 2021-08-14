package cert;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;

public class Main {

	public static void main(String[] args) {
		CertCreator cc = new CertCreator();
		cc.generateCert("cert");
		CertRequestGenerator req = new CertRequestGenerator(cc.getName());
		CertRequestGenerator req2 = new CertRequestGenerator("req2");
		X509Certificate cert = cc.generateCert("cert");
		X509Certificate cert2 = null;
		try {
			cert = CertSigner.getInstance().sign(req.generateRequests(), req.keyPair.getPrivate(), req.keyPair);
			cert2 = CertSigner.getInstance().sign(req2.generateRequests(), req2.keyPair.getPrivate(), req2.keyPair);
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException
				| CertificateException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println(cert.getPublicKey().toString());
		System.out.println(cert2.getPublicKey().toString());
		
		try {
			CertCRL.getInstance().addCert(cert);
			CertCRL.getInstance().addCert(cert2);
		} catch (InvalidKeyException | CertificateParsingException | NoSuchProviderException | SecurityException
				| SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		CertCRL.getInstance().updateCRL(cert);
		System.out.println(CertCRL.getInstance().getCRL().getRevokedCertificates());
	}
	

}
