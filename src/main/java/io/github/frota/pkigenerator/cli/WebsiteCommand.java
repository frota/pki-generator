package io.github.frota.pkigenerator.cli;

import io.github.frota.pkigenerator.service.MainService;
import io.github.frota.pkigenerator.util.HostNameUtils;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine;

import java.util.List;
import java.util.concurrent.Callable;

@CommandLine.Command(name="website", description="Generate or manage a certificate for a website.")
public class WebsiteCommand implements Callable<Integer> {

	private static final Logger log = LoggerFactory.getLogger(WebsiteCommand.class);
	
	@CommandLine.ParentCommand
	private PKIGenerator parentCommand;
	
	@CommandLine.Spec
	CommandLine.Model.CommandSpec spec;
	
	@CommandLine.Option(names="--issuer", required=true, description="Root or intermediate CA used to issue the certificate")
	private String issuer;
	
	@CommandLine.Option(names="--is-root", required=true, description="Whether the certificate should be issued by a root or intermediate CA", defaultValue="false")
	private boolean isRoot;
	
	@CommandLine.Option(names="--common-name", required=true, description="Common Name (CN) for the website certificate")
	private String commonName;
	
	@CommandLine.Option(names="--dns-names", description="DNS names to include in the certificate (can be specified multiple times)", split=",")
	private List<String> dnsNames;
	
	@CommandLine.Option(names="--ip-addrs", description="IP addresses to include in the certificate (can be specified multiple times)", split=",")
	private List<String> ipAddresses;
	
	@Override
	public Integer call() throws Exception {
		validate();
		
		MainService mainService = new MainService(parentCommand.resolveOutputDir());
		mainService.generateWebsite(commonName, issuer, isRoot, dnsNames, ipAddresses);
		return 0;
	}
	
	private void validate() {
		if (StringUtils.isBlank(commonName)) {
			throw new CommandLine.ParameterException(spec.commandLine(), "Missing option: --common-name is required.");
		}
		
		if (!HostNameUtils.isValidDns(commonName) && !HostNameUtils.isValidIp(commonName)) {
			throw new CommandLine.ParameterException(
					spec.commandLine(),
					"Invalid option: --common-name must be a valid DNS name or IP address: '" + commonName + "'");
		}
		
		if (StringUtils.isBlank(issuer)) {
			throw new CommandLine.ParameterException(spec.commandLine(), "Missing option: --issuer is required.");
		}
		
		if (!issuer.matches("[a-zA-Z0-9_]+")) {
			throw new CommandLine.ParameterException(
					spec.commandLine(),
					"Invalid option: --issuer must contain only letters, numbers and _.");
		}
		
		if (CollectionUtils.isNotEmpty(dnsNames)) {
			for (String dnsName : dnsNames) {
				if (!HostNameUtils.isValidDns(dnsName)) {
					throw new CommandLine.ParameterException(
							spec.commandLine(),
							"Invalid option: --dns-names must contain only valid DNS names: '" + dnsName + "'");
				}
			}
		}
		
		if (CollectionUtils.isNotEmpty(ipAddresses)) {
			for (String ipAddress :  ipAddresses) {
				if (!HostNameUtils.isValidIp(ipAddress)) {
					throw new CommandLine.ParameterException(
							spec.commandLine(),
							"Invalid option: --ip-addrs must contain only valid IP addresses: '" + ipAddress + "'");
				}
			}
		}
	}

}
