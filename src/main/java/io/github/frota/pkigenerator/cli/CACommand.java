package io.github.frota.pkigenerator.cli;

import io.github.frota.pkigenerator.service.MainService;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.ParentCommand;
import picocli.CommandLine.Spec;

import java.util.concurrent.Callable;

@Command(name="ca", description="Generate or handle a Certificate Authority (CA).")
public class CACommand implements Callable<Integer> {

	private static final Logger log = LoggerFactory.getLogger(CACommand.class);
	
	@ParentCommand
	private PKIGenerator parentCommand;
	
	@Spec
	CommandSpec spec;
	
	@Option(names="--common-name", required=true, description="Common Name (CN) for the (root or intermediate) CA certificate")
	private String commonName;
	
	@Option(names="--issuer", description="If set, creates an intermediate CA signed by a root CA certificate (issuer)")
	private String issuer;
	
	@Override
	public Integer call() throws Exception {
		commonName = StringUtils.normalizeSpace(commonName);
		validate();
		
		MainService mainService = new MainService(parentCommand.resolveOutputDir());
		mainService.generateCA(commonName, issuer);
		return 0;
	}
	
	private void validate() {
		if (StringUtils.isBlank(commonName)) {
			throw new CommandLine.ParameterException(spec.commandLine(), "Missing option: --common-name is required.");
		}
		
		if (!commonName.matches("[a-zA-Z0-9 ]+")) {
			throw new CommandLine.ParameterException(
					spec.commandLine(),
					"Invalid option: --common-name must contain only letters, numbers and spaces.");
		}
		
		if (StringUtils.isNotEmpty(issuer) && !issuer.matches("[a-zA-Z0-9_]+")) {
			throw new CommandLine.ParameterException(
					spec.commandLine(),
					"Invalid option: --issuer must contain only letters, numbers and _.");
		}
	}

}
