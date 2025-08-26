package io.github.frota.pkigenerator;

import io.github.frota.pkigenerator.cli.PKIGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine;

import java.security.Security;

public class Main {

	private static final Logger log = LoggerFactory.getLogger(Main.class);
	
	static {
		Security.addProvider(new BouncyCastleProvider());
	}
	
	public static void main(String[] args) {
		CommandLine cli = new CommandLine(new PKIGenerator());
		
		int exitCode = cli.execute(args);
		System.exit(exitCode);
	}

}
