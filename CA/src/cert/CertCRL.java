package cert;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi.EC;
import org.bouncycastle.x509.X509V2CRLGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;

public class CertCRL {
	
	private Date now;
	private Date nextUpdate;
	private PrivateKey caCrlPrivateKey;
	private static BigInteger id = new BigInteger("1");
	
	private X509CRL crl;
	
	private static CertCRL instance = null;
	private X509V2CRLGenerator   crlGen;
	
	private ArrayList<X509CRL> listCRL = new ArrayList<>();
	
	public CertCRL() {
		crlGen = new X509V2CRLGenerator();
		try {
			caCrlPrivateKey = EC.getInstance("RSA").generateKeyPair().getPrivate();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		
	}
	
	public X509CRL addCert(X509Certificate caCrlCert) throws InvalidKeyException, NoSuchProviderException, SecurityException, SignatureException, CertificateParsingException {
		now = new Date();
		Calendar c = Calendar.getInstance();
		c.setTime(now);
		c.add(Calendar.DATE, 30); 
		nextUpdate = c.getTime();

		crlGen = new X509V2CRLGenerator();
		for(X509CRL crl : listCRL) {
			try {
				crlGen.addCRL(crl);
			} catch (CRLException e) {
				e.printStackTrace();
			}
		}
		crlGen.setIssuerDN(caCrlCert.getIssuerX500Principal());
		 
		 
		crlGen.setThisUpdate(now);
		crlGen.setNextUpdate(nextUpdate);
		crlGen.setSignatureAlgorithm(caCrlCert.getSigAlgName());
		 
		 
		crlGen.addCRLEntry(caCrlCert.getSerialNumber(), now, CRLReason.privilegeWithdrawn);
		crlGen.addExtension(X509Extensions.AuthorityKeyIdentifier,
		                  false, new AuthorityKeyIdentifierStructure(caCrlCert));
		crlGen.addExtension(X509Extensions.CRLNumber,
		                  false, new CRLNumber(id));

		crl = crlGen.generateX509CRL(caCrlPrivateKey, "BC");
		listCRL.add(crl);
		id.add(BigInteger.ONE);
		return crl;
		 
	}
	
	public void updateCRL(X509Certificate caCrlCert) {
		
		X509CRL existingCRL = crl;

		crlGen = new X509V2CRLGenerator();
		for(X509CRL crl : listCRL) {
			try {
				crlGen.addCRL(crl);
			} catch (CRLException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		crlGen.setIssuerDN(new X500Principal("CN=Test CA"));
		 
		 
		crlGen.setThisUpdate(now);
		crlGen.setNextUpdate(nextUpdate);
		crlGen.setSignatureAlgorithm(existingCRL.getSigAlgName());
		try {
			crlGen.addCRL(existingCRL);
		} catch (CRLException e2) {
			// TODO Auto-generated catch block
			e2.printStackTrace();
		}
		 
		crlGen.addCRLEntry(caCrlCert.getSerialNumber(), now, CRLReason.privilegeWithdrawn);
		 
		 
		try {
			crlGen.addExtension(X509Extensions.AuthorityKeyIdentifier,
			                  false, new AuthorityKeyIdentifierStructure(caCrlCert));
		} catch (CertificateParsingException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		crlGen.addExtension(X509Extensions.CRLNumber,
		                  false, new CRLNumber(caCrlCert.getSerialNumber()));
		 
		 
		try {
			crl = crlGen.generateX509CRL(caCrlPrivateKey, "BC");
		} catch (InvalidKeyException | NoSuchProviderException | SecurityException | SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}		
		
	}
		
	public static CertCRL getInstance() {
		if(instance == null)
			instance = new CertCRL();
		return instance;
	}
	
	public X509CRL getCRL() {
		return crl;
	}
}
