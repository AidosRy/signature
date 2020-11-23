import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

import java.io.*;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

public class Sign{

    private static final String keyStorePassword="fqljc26";
    private static final String certificateAlias="jvmfy";
    static KeyStore keyStore;
    static PrivateKey privateKey;
    private static Store certs;
    static private Certificate[] certificateChain;
    static {
        try{
            keyStore=getKeyStore();
            privateKey = (PrivateKey) keyStore.getKey(certificateAlias, keyStorePassword.toCharArray());
            certificateChain = Optional.ofNullable(keyStore.getCertificateChain(certificateAlias))
                    .orElseThrow(() -> (new IOException("Could not find a proper certificate chain")));
        }
        catch (Exception e) {e.printStackTrace();}
    }

    public static void main(String[] args) throws Exception {
        byte[] arr = signData(generatePdf(), (X509Certificate) certificateChain[0], privateKey);
        System.out.println(verifSignedData(arr));
        byte[] empty = generatePdf();
        System.out.println(verifSignedData(empty));
    }

    public static byte[] signData(
            byte[] data,
            X509Certificate signingCertificate,
            PrivateKey signingKey) throws Exception {

        byte[] signedMessage;
        List<X509Certificate> certList = new ArrayList<>();
        CMSTypedData cmsData= new CMSProcessableByteArray(data);
        certList.add(signingCertificate);
       certs  = new JcaCertStore(certList);

        CMSSignedDataGenerator cmsGenerator = new CMSSignedDataGenerator();
        ContentSigner sha256signer
                = new JcaContentSignerBuilder("SHA256withRSA").build(signingKey);
        cmsGenerator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder().build()).build(sha256signer, signingCertificate));
        cmsGenerator.addCertificates(certs);

        CMSSignedData cms = cmsGenerator.generate(cmsData, true);
        signedMessage = cms.getEncoded();
        return signedMessage;
    }

    public static boolean verifSignedData(byte[] signedData)
            throws Exception {

        ByteArrayInputStream inputStream
                = new ByteArrayInputStream(signedData);
        ASN1InputStream asnInputStream = new ASN1InputStream(inputStream);
        CMSSignedData cmsSignedData = new CMSSignedData(
                ContentInfo.getInstance(asnInputStream.readObject()));

        SignerInformationStore signers
                = cmsSignedData.getSignerInfos();
        SignerInformation signer = signers.getSigners().iterator().next();
        Collection<X509CertificateHolder> certCollection
                = certs.getMatches(signer.getSID());
        X509CertificateHolder certHolder = certCollection.iterator().next();

        return signer
                .verify(new JcaSimpleSignerInfoVerifierBuilder()
                        .build(certHolder));
    }

    static byte[] generatePdf() throws IOException {
        PDDocument pdDocument = new PDDocument();
        PDPage pdPage = new PDPage();
        pdDocument.addPage(pdPage);
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        pdDocument.save(byteArrayOutputStream);
        pdDocument.close();
        return byteArrayOutputStream.toByteArray();
    }

    private static KeyStore getKeyStore() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore keyStore = KeyStore.getInstance("jks");
        File key = new File("C:\\Users\\a_rustem\\Desktop\\signature_files\\keystore.jks");
        keyStore.load(new FileInputStream(key), keyStorePassword.toCharArray());
        return keyStore;
    }

}
