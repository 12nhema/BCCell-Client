package com.integra.usbtokensign;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Scanner;
import java.util.regex.Pattern;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentCatalog;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.encryption.InvalidPasswordException;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.pdmodel.interactive.form.PDField;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.context.support.StaticApplicationContext;

public class PDFUSBTokenSign {

	// private static final Throwable UnrecoverableKeyException = null;
	static KeyStore ks = null;
	static PrivateKey pk = null;
	static Certificate[] chain = null;
	static BouncyCastleProvider bcp = null;
	// For windows
	// static String pkcs11Config =
	// "name=eToken\nlibrary=C:\\Windows\\System32\\eps2003csp11v2.dll";
	static String certName = null;
//	static String s = null;

	public static JSONObject presetup(String configPath, String password, String alias) throws IOException {
		JSONObject jsRes = new JSONObject();
		X500Name x500name = null;
		boolean exists = false;
		boolean isTokenValid=false;
		try {
			ByteArrayInputStream pkcs11ConfigStream = new ByteArrayInputStream(configPath.getBytes());
			@SuppressWarnings("restriction")
			sun.security.pkcs11.SunPKCS11 providerPKCS11 = new sun.security.pkcs11.SunPKCS11(pkcs11ConfigStream);
			java.security.Security.addProvider(providerPKCS11);
			KeyStore keyStore = KeyStore.getInstance("PKCS11");
			
			
			// checking whether a file exists which contains count of entered incorrect
			// password
			
			File fileexists = new File("PinIncorrectDeatils.txt");
			exists = fileexists.exists();
			if (exists) {
				// reading the file to check no of times entered password is incoorect
				String data = readFile();
				// myWriter = new FileWriter("PinIncorrectDeatils.txt");
				String countvalue = data.split(":")[1];
				int intcount = Integer.parseInt(countvalue);
				// checking if the entered password is wrong to avoid locking the token after 5
				// continuous failure DSC PIN_INCORRECT key load attempts
				if (intcount < 5) {
					keyStore.load(null, password.toCharArray());
					deleteFile();
				} else {
					jsRes.put("status", "FAILURE");
					jsRes.put("statusDetails",
							"Number of attempts for entering password is exceeded. Further attempting will lead to locking of the token. Please login to your DSC token application with correct password and retry.");
					return jsRes;
				}
			} else {
				keyStore.load(null, password.toCharArray());
			}
			
		
		  // Code to get the alias form token
			@SuppressWarnings("rawtypes")
			Enumeration enumeration = keyStore.aliases();
			while (enumeration.hasMoreElements()) {
				String aliaselement = (String) enumeration.nextElement();
				//System.out.println(aliaselement);
				Certificate certificate = keyStore.getCertificate(aliaselement);
				// to get the subject from certificate and subject contents
				x500name = new JcaX509CertificateHolder((java.security.cert.X509Certificate) certificate).getSubject();
				// to check the type of certificate been used for signing by passing the
				// aliaselement
				X509Certificate cert = (java.security.cert.X509Certificate) certificate;
				boolean[] KeyUsageArray = cert.getKeyUsage();
//				System.out.println(KeyUsageArray);
//				for (int i = 0; i < KeyUsageArray.length; i++) {
//					System.out.println("KeyUsageArray:"+ KeyUsageArray[i]);
//					
//				}
				// KeyUsageArray[0]-0 because digitical certifictae is present in 0 position
				boolean digitalCertificate = KeyUsageArray[0];
				if (digitalCertificate) {
					// System.out.println("digitalCertificate");y
					alias = aliaselement;
					System.out.println("alias:"+alias);
					isTokenValid=true;
					break;
				} else {
					jsRes.put("status", "FAILURE");
					jsRes.put("statusDetails", "Invalid Token. Please Check whether token contains a Digital Signature");
				}
			}
			//only returns the response if there isTokenValid is false
			if(!isTokenValid) {
				return jsRes;
			}
			RDN cn = x500name.getRDNs(BCStyle.CN)[0];
			RDN pincode = x500name.getRDNs(BCStyle.POSTAL_CODE)[0];
			RDN st = x500name.getRDNs(BCStyle.ST)[0];
			// converting to strings
			certName = IETFUtils.valueToString(cn.getFirst().getValue());
			String pinCode = IETFUtils.valueToString(pincode.getFirst().getValue());
			String state = IETFUtils.valueToString(st.getFirst().getValue());

			KeyStore.PrivateKeyEntry entry = null;
			if (keyStore.isKeyEntry(alias)) {
				entry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, null);
			} else {
				throw new Exception(
						"Invalid alias name. No private key found with the given alias name in smart card keystore.");
			}
			pk = entry.getPrivateKey();
			chain = keyStore.getCertificateChain(alias);
			bcp = new BouncyCastleProvider();
			Security.insertProviderAt(bcp, 1);
			jsRes.put("status", "SUCCESS");
			jsRes.put("statusDetails", "E-Token Exixts");
			jsRes.put("cn", certName);
			jsRes.put("pinCode", pinCode);
			jsRes.put("state", state);
		} catch (IOException e1) {
			try {
				String cause = e1.getCause() + "";
				// checking the cause is "UnrecoverableKeyException' in IO exception as stated
				// in the method documentation which indicates wrong password
				if (cause.equalsIgnoreCase("java.security.UnrecoverableKeyException")) {
					jsRes.put("status", "FAILURE");
					jsRes.put("statusDetails", "E-Token password is incorrect");
					tokendetailsFile();
				} else {
					jsRes.put("status", "FAILURE");
					jsRes.put("statusDetails", e1.getMessage());
				}
				// e1.getCause()
			} catch (JSONException e2) {
				e2.printStackTrace();
			}
		} catch (Exception e) {
			e.printStackTrace();
			try {
				jsRes.put("status", "FAILURE");
				jsRes.put("statusDetails", "E-Token NOT present");
				jsRes.put("errorMsg", e.getMessage());
			} catch (JSONException e1) {
				e1.printStackTrace();
			}
		}
		return jsRes;
	}

	public static String getDisMSGFormat(JSONArray displayInfo) {
		String displayMsg = "";
		try {
			int length = displayInfo.length();
			Calendar currentDat = Calendar.getInstance();
			SimpleDateFormat apperenceDateFormat = new SimpleDateFormat("dd-MM-yyyy HH:mm:ss");
			Date apperenceCurrentDate = currentDat.getTime();
			String apperenceStrCurrentDate = apperenceDateFormat.format(apperenceCurrentDate);

			if (length > 0) {
				for (int i = 0; i < length; i++) {
					JSONObject json = displayInfo.getJSONObject(i);
					String temp = json.getString("displayMsg");
					String res = "";
					if (temp.contains("$$cn$$")) {
						res = temp.replace("$$cn$$", certName);
						displayMsg += res;
					} else if (temp.contains("$$date$$")) {
						res = temp.replace("$$date$$", apperenceStrCurrentDate);
						displayMsg += res;
					} else {
						displayMsg += temp;
					}
				}
			}
		} catch (JSONException e) {
			e.printStackTrace();
		}
		return displayMsg;
	}

	public static PDDocument addSignatureUsingUSBToken(String filePath, String inputImgPath, JSONObject signCoordinates,
			String configPath, String password, String alias, String displayInfo) throws IOException {

		presetup(configPath, password, alias);

		try (PDDocument pdDocument = PDDocument.load(new FileInputStream(new File(filePath)));) {

			String signDisplayInfo = getDisMSGFormat(new JSONArray(displayInfo));

			String x = signCoordinates.getString("x").trim();
			String y = signCoordinates.getString("y").trim();
			String signPage = signCoordinates.getString("signPage").trim();
			String width = signCoordinates.getString("width").trim();
			String height = signCoordinates.getString("height").trim();
			PDSignature pds = null;
			int pageNum = 0;
			String[] signpages = null;

			File imgFile = new File(inputImgPath);

			PDAcroForm acroForm = pdDocument.getDocumentCatalog().getAcroForm();
			if (acroForm == null) {
				pdDocument.getDocumentCatalog().setAcroForm(acroForm = new PDAcroForm(pdDocument));
			}
			acroForm.setSignaturesExist(true);
			acroForm.setAppendOnly(true);
			acroForm.getCOSObject().setDirect(true);

			pds = new PDSignature();
			pds.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
			pds.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
			pds.setSignDate(Calendar.getInstance());

			PDPage pdpage = pdDocument.getPage(0);

			PDImageXObject pdImage = null;
			if (imgFile.exists()) {
				pdImage = PDImageXObject.createFromFileByContent(imgFile, pdDocument);
			}

			float totalheight = pdpage.getMediaBox().getHeight();
			float totalwidth = pdpage.getMediaBox().getWidth();
			PDRectangle rectangle = null;

			if ("L".equalsIgnoreCase(signPage)) {
				pageNum = pdDocument.getNumberOfPages() - 1;
			} else if ("F".equalsIgnoreCase(signPage)) {
				pageNum = 0;
			} else if ("P".equalsIgnoreCase(signPage)) {
				pageNum = -2; // -2 represents all mentioned pages in an array
				signPage = signCoordinates.getString("pages");
				signPage = signPage.substring(signPage.indexOf("[") + 1, signPage.indexOf("]"));
				signpages = signPage.split(",");
			} else if ("A".equalsIgnoreCase(signPage)) {
				pageNum = -1; // -1 represents all pages
			} else {
				pageNum = Integer.parseInt(signCoordinates.getString("signPage")) - 1;
			}

			y = (totalheight - (Float.parseFloat(y)) - Float.parseFloat(height)) + "";
			float xEnd = Float.parseFloat(x) + Float.parseFloat(width);
			if (xEnd > totalwidth) {
				float diff = xEnd - totalwidth;
				float newX = Float.parseFloat(x) - diff;
				x = newX + "";
			}

			rectangle = new PDRectangle(Float.parseFloat(x), Float.parseFloat(y), Float.parseFloat(width),
					Float.parseFloat(height));

			List<PDField> acroFormFields = acroForm.getFields();
			PDSignatureField signatureField = new PDSignatureField(acroForm);
			acroForm.setSignaturesExist(true);
			acroForm.setAppendOnly(true);
			acroForm.getCOSObject().setDirect(true);
			signatureField.setValue(pds);
			acroFormFields.add(signatureField);

			pdDocument.addSignature(pds, new SignatureInterface() {

				@SuppressWarnings("rawtypes")
				@Override
				public byte[] sign(InputStream content) throws IOException {
					try {
						List<Certificate> certList = new ArrayList<>();
						certList.addAll(Arrays.asList(chain));

						Store certs = new JcaCertStore(certList);

						CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

						org.bouncycastle.asn1.x509.Certificate cert = org.bouncycastle.asn1.x509.Certificate
								.getInstance(chain[0].getEncoded());

						ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA256WithRSA").build(pk);

						gen.addSignerInfoGenerator(
								new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build())
										.build(sha1Signer, new X509CertificateHolder(cert)));

						gen.addCertificates(certs);

						CMSProcessableInputStream msg = new CMSProcessableInputStream(content);

						CMSSignedData signedData = gen.generate(msg, false);

						return signedData.getEncoded();
					}

					catch (GeneralSecurityException | CMSException | OperatorCreationException e) {
						System.err.println("Error while creating pkcs7 signature.");
						e.printStackTrace();
					}
					throw new RuntimeException("Problem while preparing signature");
				}
			});

			if (pageNum == -1) {
				for (PDPage pdPage : pdDocument.getPages()) {
					AddVisibleSignature.createVisualSignatureTemplate(pdDocument, signatureField, pdPage, rectangle,
							pdImage, signDisplayInfo);
				}
			} else if (pageNum == -2) {
				for (String pageNo : signpages) {
					PDPage pdPage = pdDocument.getPage(Integer.parseInt(pageNo) - 1);
					AddVisibleSignature.createVisualSignatureTemplate(pdDocument, signatureField, pdPage, rectangle,
							pdImage, signDisplayInfo);
				}
			} else {
				PDPage pdPage = pdDocument.getPage(pageNum);
				AddVisibleSignature.createVisualSignatureTemplate(pdDocument, signatureField, pdPage, rectangle,
						pdImage, signDisplayInfo);
			}

			pdDocument.saveIncremental(new FileOutputStream(new File(filePath)));
			return pdDocument;
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	// PDF signing based on document hash
	public static byte[] sign(byte[] hash)
			throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		try {
			PrivateKey privKey = pk;
			List<Certificate> certList = new ArrayList<>();
			certList.addAll(Arrays.asList(chain));

			JcaCertStore certs = new JcaCertStore(certList);

			CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

			Attribute attr = new Attribute(CMSAttributes.messageDigest, new DERSet(new DEROctetString(hash)));

			ASN1EncodableVector v = new ASN1EncodableVector();
			v.add(attr);

			SignerInfoGeneratorBuilder builder = new SignerInfoGeneratorBuilder(new BcDigestCalculatorProvider())
					.setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(new AttributeTable(v)));

//			AlgorithmIdentifier sha256withRSA = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256withRSA");

			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			InputStream in = new ByteArrayInputStream(chain[0].getEncoded());
			X509Certificate cert = (X509Certificate) certFactory.generateCertificate(in);

			ContentSigner sha256Signer = new JcaContentSignerBuilder("SHA256WithRSA").build(privKey);
			gen.addSignerInfoGenerator(builder.build(sha256Signer, new JcaX509CertificateHolder(cert)));

			gen.addCertificates(certs);

			CMSSignedData s = gen.generate(new CMSAbsentContent(), false);
			return s.getEncoded();

		} catch (GeneralSecurityException e) {
			throw new IOException(e);
		} catch (CMSException e) {
			throw new IOException(e);
		} catch (OperatorCreationException e) {
			throw new IOException(e);
		}
	}

	// for deleted the file
	public static void deleteFile() {
		File myObj = new File("PinIncorrectDeatils.txt");
		myObj.delete();
	}

	// checking if a file is present or no and creating/writing into file operations
	// until the count is reached to 5
	public static void tokendetailsFile() throws IOException {
		int count = 1;
		String data = null;
		FileWriter myWriter = null;
		String countvalue;
		boolean exists = false;
		try {
			File fileexists = new File("PinIncorrectDeatils.txt");
			exists = fileexists.exists();
			// if file doesn't exists creating one file and writing into it the counts of
			// incorrect password entered
			if (!exists) {
				myWriter = new FileWriter(fileexists);
				myWriter.write("Token password incorrect:" + count);
			} else {
				// writing into an already file and increasing the incorrect password count by 1
				// each time incorrect password is entered
				data = readFile();
				myWriter = new FileWriter("PinIncorrectDeatils.txt");
				countvalue = data.split(":")[1];
				int intcount = Integer.parseInt(countvalue) + 1;
				myWriter.write("Token password incorrect:" + intcount);
			}
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			if (myWriter != null) {
				myWriter.close();
			}
		}
	}

	// reading the file for checking the no of key load attempts failures
	public static String readFile() {
		String data = null;
		File myObj = new File("PinIncorrectDeatils.txt");
		try (Scanner myReader = new Scanner(myObj);) {
			while (myReader.hasNextLine()) {
				data = myReader.nextLine();
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		return data;
	}

}
