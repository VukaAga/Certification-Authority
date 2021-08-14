package cert;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;

public class CertSigner {
	
	static BigInteger id;
	
	static CertSigner instance;
	
	public CertSigner() {
		id = new BigInteger("1");
	}
	
	public  X509Certificate sign(PKCS10CertificationRequest inputCSR, PrivateKey caPrivate, KeyPair pair)
	        throws InvalidKeyException, NoSuchAlgorithmException,
	        NoSuchProviderException, SignatureException, IOException, CertificateException {   

	    AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder()
	            .find("SHA1withRSA");
	    AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder()
	            .find(sigAlgId);

	    AsymmetricKeyParameter foo = PrivateKeyFactory.createKey(caPrivate
	            .getEncoded());
	    SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(pair
	            .getPublic().getEncoded());

	    org.bouncycastle.pkcs.PKCS10CertificationRequest pk10Holder = new org.bouncycastle.pkcs.PKCS10CertificationRequest(inputCSR);
	    
	    X509v1CertificateBuilder myCertificateGenerator = new X509v1CertificateBuilder(
	            new X500Name("CN=issuer"), id, new Date(
	                    System.currentTimeMillis()), new Date(
	                    System.currentTimeMillis() + 30 * 365 * 24 * 60 * 60
	                            * 1000), pk10Holder.getSubject(), keyInfo);

	    ContentSigner sigGen = null;
		try {
			sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId)
			        .build(foo);
		} catch (OperatorCreationException e) {
			e.printStackTrace();
		}        

	    X509CertificateHolder holder = myCertificateGenerator.build(sigGen);
	    org.bouncycastle.asn1.x509.Certificate eeX509CertificateStructure = holder.toASN1Structure();
	    CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

	    InputStream is1 = new ByteArrayInputStream(eeX509CertificateStructure.getEncoded());
	    X509Certificate theCert = (X509Certificate) cf.generateCertificate(is1);
	    is1.close();
	    id = id.add(BigInteger.ONE);
	    return theCert;
	}
	
	public static CertSigner getInstance() {
		if (instance == null) {
			instance = new CertSigner();
		}
		return instance;
	}

}
