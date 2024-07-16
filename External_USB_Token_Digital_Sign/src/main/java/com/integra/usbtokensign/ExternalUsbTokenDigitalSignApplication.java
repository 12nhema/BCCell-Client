package com.integra.usbtokensign;

import java.io.Console;
import java.io.IOException;
import java.util.Scanner;

import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class ExternalUsbTokenDigitalSignApplication {
//	windows
	static String pkcs11Config = "name=eToken\nlibrary=C:\\Windows\\System32\\eps2003csp11v2.dll";
	
	//Linux
//	static String pkcs11Config ="name=eToken\nlibrary=/ePass-Linux/ePass2003-Linux-x64/ePass2003-Linux-x64/redist/libcastle.so.1.0.0";
	public static String tokenPwd = "";

	public static void main(String[] args) throws IOException, JSONException {

		System.out.println("===========================================================");
		System.out.println("=            External_USB_Token_Digital_Sign              =");
		System.out.println("=                 Version 00_00_10                        =");
		System.out.println("===========================================================");
		SpringApplication.run(ExternalUsbTokenDigitalSignApplication.class, args);

		// Scanner scanner = new Scanner(System.in);

		// prompt for the user's name
		System.out.println();
		System.out.println("----------------------Application Started Successfully--------------------- ");
		// System.out.println("Enter your e-Token password: ");

		// get their input as a String
		// tokenPwd = scanner.next();
//		scanner.close();
		consoleMethod();
	}

	public static void consoleMethod() {
		Console cnsl = null;
		cnsl = System.console();
		if (cnsl != null) {
			char[] pwd = cnsl.readPassword("Enter your e-Token Password: ", new Object[0]);
			tokenPwd = new String(pwd);
			presetUp();
		}

	}

	public static void presetUp() {
		String configPath = pkcs11Config;
		String alias = null;
		try {
			JSONObject tokenresp = PDFUSBTokenSign.presetup(configPath, tokenPwd, alias);
			//System.out.println("tokenresp:"+tokenresp);
			if (("SUCCESS").equalsIgnoreCase(tokenresp.getString("status"))) {
				System.out.println("DSC Token access granted.");
				System.out.println("CertificateName:" + tokenresp.getString("cn"));
			} else {
				System.out.println(tokenresp.getString("statusDetails"));
				consoleMethod();
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

}
