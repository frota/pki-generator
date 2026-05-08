package io.github.frota.pkigenerator.cli;

import io.github.frota.pkigenerator.service.MainService;
import org.apache.commons.lang3.StringUtils;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.ParentCommand;
import picocli.CommandLine.Spec;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Callable;

@Command(name="clone", description="Clone an existing certificate and sign it with a local CA.")
public class CloneCommand implements Callable<Integer> {

	@ParentCommand
	private PKIGenerator parentCommand;
	
	@Spec
	CommandSpec spec;
	
	@Option(names="--source-cert", required=true, description="Existing X.509 certificate to clone (PEM or DER)")
	private Path sourceCertificate;
	
	@Option(names="--issuer", required=true, description="Root or intermediate CA used to issue the cloned certificate")
	private String issuer;
	
	@Option(names="--is-root", required=true, description="Whether the issuer is a root or intermediate CA", defaultValue="false")
	private boolean isRoot;
	
	@Option(names="--name", description="Output folder/file name. Defaults to the source certificate CN or serial number")
	private String name;
	
	@Override
	public Integer call() throws Exception {
		validate();
		
		MainService mainService = new MainService(parentCommand.resolveOutputDir());
		mainService.cloneCertificate(sourceCertificate, issuer, isRoot, name);
		return 0;
	}
	
	private void validate() {
		if (sourceCertificate == null) {
			throw new CommandLine.ParameterException(spec.commandLine(), "Missing option: --source-cert is required.");
		}
		
		if (Files.notExists(sourceCertificate)) {
			throw new CommandLine.ParameterException(
					spec.commandLine(),
					"Invalid option: --source-cert file doesn't exist: " + sourceCertificate);
		}
		
		if (StringUtils.isBlank(issuer)) {
			throw new CommandLine.ParameterException(spec.commandLine(), "Missing option: --issuer is required.");
		}
		
		if (!issuer.matches("[a-zA-Z0-9_]+")) {
			throw new CommandLine.ParameterException(
					spec.commandLine(),
					"Invalid option: --issuer must contain only letters, numbers and _.");
		}
		
		if (StringUtils.isNotBlank(name) && !name.matches("[a-zA-Z0-9_ -]+")) {
			throw new CommandLine.ParameterException(
					spec.commandLine(),
					"Invalid option: --name must contain only letters, numbers, spaces, - and _.");
		}
	}

}
