package io.github.frota.pkigenerator.cli;

import io.github.frota.pkigenerator.service.MainService;
import io.github.frota.pkigenerator.util.CertificateTypeEnum;
import io.github.frota.pkigenerator.util.CpfCnpjUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine;

import java.util.concurrent.Callable;

@CommandLine.Command(name="icpcnpj", description="Generate an ICP-Brasil certificate (CNPJ).")
public class IcpCnpjCommand implements Callable<Integer> {

	private static final Logger log = LoggerFactory.getLogger(IcpCnpjCommand.class);
	
	@CommandLine.ParentCommand
	private PKIGenerator parentCommand;
	
	@CommandLine.Spec
	CommandLine.Model.CommandSpec spec;
	
	@CommandLine.Option(names="--common-name", required=true, description="Common Name (CN) for the ICP-Brasil certificate (CNPJ)")
	private String commonName;
	
	@CommandLine.Option(names="--issuer", required=true, description="Root or intermediate CA used to issue the certificate")
	private String issuer;
	
	@CommandLine.Option(names="--is-root", required=true, description="Whether the certificate should be issued by a root or intermediate CA", defaultValue="false")
	private boolean isRoot;
	
	@CommandLine.Option(names="--cnpj", required=true, description="CNPJ for the certificate")
	private String cnpj;
	
	@CommandLine.Option(names="--email", description="E-mail")
	private String email;
	
	@CommandLine.Option(names="--resp-name", required=true, description="Responsible person name")
	private String personName;
	
	@CommandLine.Option(names="--resp-cpf", required=true, description="Responsible person CPF")
	private String personCpf;
	
	@CommandLine.Option(names="--cert-type", description="Certificate type: ${COMPLETION-CANDIDATES}", defaultValue="A1")
	private CertificateTypeEnum certType;
	
	@Override
	public Integer call() throws Exception {
		commonName = StringUtils.upperCase(StringUtils.normalizeSpace(commonName));
		cnpj = StringUtils.upperCase(cnpj);
		email = StringUtils.upperCase(StringUtils.trim(email));
		personName = StringUtils.upperCase(StringUtils.normalizeSpace(personName));
		validate();
		
		MainService mainService = new MainService(parentCommand.resolveOutputDir());
		mainService.generateIcpCnpj(commonName, issuer, isRoot, cnpj, email, personName, personCpf, certType);
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
		
		if (StringUtils.isBlank(issuer)) {
			throw new CommandLine.ParameterException(spec.commandLine(), "Missing option: --issuer is required.");
		}
		
		if (!issuer.matches("[a-zA-Z0-9_]+")) {
			throw new CommandLine.ParameterException(
					spec.commandLine(),
					"Invalid option: --issuer must contain only letters, numbers and _.");
		}
		
		if (StringUtils.isBlank(cnpj) || !CpfCnpjUtils.isCnpj(cnpj)) {
			throw new CommandLine.ParameterException(
					spec.commandLine(),
					"Invalid option: --cnpj must be a valid CNPJ.");
		}
		
		if (StringUtils.isBlank(email)) {
			throw new CommandLine.ParameterException(
					spec.commandLine(),
					"Missing option: --email is required.");
		}
		
		if (StringUtils.isBlank(personName)) {
			throw new CommandLine.ParameterException(
					spec.commandLine(),
					"Missing option: --resp-name is required.");
		}
		
		if (StringUtils.isBlank(personCpf) || !CpfCnpjUtils.isCpf(personCpf)) {
			throw new CommandLine.ParameterException(
					spec.commandLine(),
					"Invalid option: --resp-cpf must be a valid CPF.");
		}
	}

}
