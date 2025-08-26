package io.github.frota.pkigenerator.cli;

import io.github.frota.pkigenerator.util.AppConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.Callable;

@Command(name="pki-generator",
	version="0.0.1",
	mixinStandardHelpOptions=true,
	subcommands={
		CACommand.class,
		IcpCnpjCommand.class,
		IcpCpfCommand.class,
		WebsiteCommand.class
	})
public class PKIGenerator implements Callable<Integer> {

	private static final Logger log = LoggerFactory.getLogger(PKIGenerator.class);
	
	@Option(names="--output-dir", description="Base directory for generated files (default: ${DEFAULT-VALUE})",
			defaultValue="${sys:user.home}/" + AppConstants.DEFAULT_OUTPUT_FOLDER, scope=picocli.CommandLine.ScopeType.INHERIT)
	private String outputDir;
	
	@Override
	public Integer call() throws Exception {
		log.info("Running pki-generator...");
		return 0;
	}
	
	public Path resolveOutputDir() {
		return Paths.get(outputDir)
				.toAbsolutePath()
				.normalize();
	}

}
