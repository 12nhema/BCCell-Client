package com.integra.usbtokensign;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Date;

import javax.servlet.http.HttpServletRequest;

import org.apache.tomcat.util.codec.binary.Base64;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@CrossOrigin(origins = "*")
public class WSController {
	
	//check token is inserted or not
	@PostMapping(value = "TOKENSIGN/checkTokenExistence", consumes = { "application/JSON" }, produces = {
			"application/JSON" })
	public String checkTokenExistence(@RequestBody String tokenInfo) {
		System.out.println("In checkTokenExistence External Service ");
		JSONObject jsRes = new JSONObject();
		try {
			JSONObject input = new JSONObject(tokenInfo);
//			String password = new String(Base64.decodeBase64(input.getString("password")));
			String password = ExternalUsbTokenDigitalSignApplication.tokenPwd;
			String configPath = new String(Base64.decodeBase64(input.getString("configPath")));
			String alias = new String(Base64.decodeBase64(input.getString("alias")));

			jsRes = PDFUSBTokenSign.presetup(configPath, password, alias);
			// jsRes = PDFUSBTokenSign.presetup(configPath, tokenPwd, alias);
//			if (("SUCCESS").equalsIgnoreCase(jsRes.getString("status"))) {
//				System.out.println("DSC Token access granted.");
//
//			} else {
//				System.out.println(
//						"DSC Token access failed. Please check if token is connected and valid password is entered.");
//			}
		} catch (Exception e) {
			try {
				jsRes.put("status", "FAILURE");
				jsRes.put("statusDetails", "In checkTokenExistence External Service " + e.getMessage());
			} catch (JSONException e1) {
				e1.printStackTrace();
			}
		}
		return jsRes.toString();
	}

	//generates the signed hash by taking document hash
	@PostMapping(value = "TOKENSIGN/getDSCTokenSign", consumes = { "application/JSON" }, produces = {
			"application/JSON" })
	public String getDSCTokenSign(@RequestBody String tokenInfo, HttpServletRequest requestContext)
			throws JSONException, UnsupportedEncodingException {
		System.out.println("In getDSCTokenSign External Service ");
		String ip = requestContext.getRemoteAddr();
		JSONObject jsRes = new JSONObject();

		JSONObject input = new JSONObject(tokenInfo);
		String status = "";
		String encodedBase64SignedHash = null;
		try {

//			String password = new String(Base64.decodeBase64(input.getString("password")));
			String password = ExternalUsbTokenDigitalSignApplication.tokenPwd;
			String configPath = new String(Base64.decodeBase64(input.getString("configPath")));
			String alias = new String(Base64.decodeBase64(input.getString("alias")));
//			String filePath = "SignDocument.pdf";

			byte[] pdfbyte = Base64.decodeBase64(input.getString("docHash"));
			
			//writing pdf object to a file (not in use older version)
//			FileOutputStream out = new FileOutputStream(new File(filePath));
//			out.write(pdfbyte);
//			out.close();

//			JSONObject signCoordinates = new JSONObject(input.getString("signCoordinates"));
//			PDFUSBTokenSign.addSignatureUsingUSBToken(filePath, "", signCoordinates, configPath, password, alias,
//					input.getString("signDisplayInfo"));

			// presetup for certificate
			PDFUSBTokenSign.presetup(configPath, password, alias);
			byte[] signedHash = PDFUSBTokenSign.sign(pdfbyte);
			encodedBase64SignedHash = new String(Base64.encodeBase64(signedHash));

			//writing pdf object to a file (not in use older version)
//			File originalFile = new File(filePath);
//			String encodedBase64 = null;
//			try {
//				FileInputStream fileInputStreamReader = new FileInputStream(originalFile);
//				byte[] bytes = new byte[(int) originalFile.length()];
//				fileInputStreamReader.read(bytes);
//				fileInputStreamReader.close();
//				encodedBase64 = new String(Base64.encodeBase64(bytes));

//			} catch (FileNotFoundException e) {
//				e.printStackTrace();
//			} catch (IOException e) {
//				e.printStackTrace();
//			}

//			String toDeletePath = originalFile.getAbsolutePath();

//			boolean isDeleted = new File(toDeletePath).delete();
			jsRes.put("status", "SUCCESS");
			jsRes.put("signerName", PDFUSBTokenSign.certName);
			jsRes.put("pdfdata", encodedBase64SignedHash);

			status = "SIGNED";
		} catch (JSONException | FileNotFoundException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
			status = e1.getMessage();
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
			status = e1.getMessage();
		} catch (InvalidKeyException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
			status = e1.getMessage();
		} catch (NoSuchAlgorithmException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
			status = e1.getMessage();
		} catch (SignatureException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
			status = e1.getMessage();
		} finally {
			FileWriter writer;
//			FileWriter writer2;
			try {
				writer = new FileWriter("DSC_Token_Sign_Log.txt", true);
				BufferedWriter bufferedWriter = new BufferedWriter(writer);
				bufferedWriter.write("BC MID-" + input.getString("mid") + "|Company-" + input.getString("company")
						+ "|Bank-" + input.getString("group") + "|Date-" + new Date() + "|BC Name-"
						+ input.getString("name") + "|Status-" + status);
				bufferedWriter.newLine();
				bufferedWriter.close();
				
				//writing output to a file (debug mode)
//				writer2 = new FileWriter("DSC_Token_Output.txt", true);
//				BufferedWriter bufferedWriter2 = new BufferedWriter(writer2);
//				bufferedWriter2.write("Without URL encode : "+jsRes.toString());
//				bufferedWriter2.newLine();
//				bufferedWriter2.write("with URL encode"+URLEncoder.encode(jsRes.toString(), "UTF-8"));
//				bufferedWriter2.close();
			} catch (IOException e) {
				e.printStackTrace();
			}

		}

		return jsRes.toString();
	}
}
