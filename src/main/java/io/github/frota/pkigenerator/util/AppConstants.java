package io.github.frota.pkigenerator.util;

import java.nio.file.Path;
import java.nio.file.Paths;

public final class AppConstants {

	public static final String ROOT_CA_FOLDER =         "0_root";
	public static final String INTERMEDIATE_CA_FOLDER = "1_intermediate";
	public static final String WEBSITE_FOLDER =         "2_website";
	public static final String ICP_CPF_FOLDER =         "3_icp_cpf";
	public static final String ICP_CNPJ_FOLDER =        "4_icp_cnpj";
	
	public static final String DEFAULT_OUTPUT_FOLDER = ".pki-generator";
	
	private AppConstants() {}
	
	public static Path defaultOutputDir() {
		return Paths.get(System.getProperty("user.home"), DEFAULT_OUTPUT_FOLDER)
				.toAbsolutePath()
				.normalize();
	}

}
