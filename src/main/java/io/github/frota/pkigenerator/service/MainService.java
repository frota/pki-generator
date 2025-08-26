package io.github.frota.pkigenerator.service;

import com.github.slugify.Slugify;
import io.github.frota.pkigenerator.model.CARequest;
import io.github.frota.pkigenerator.model.ICPBrasilCNPJRequest;
import io.github.frota.pkigenerator.model.ICPBrasilCPFRequest;
import io.github.frota.pkigenerator.model.WebsiteRequest;
import io.github.frota.pkigenerator.util.AppConstants;
import io.github.frota.pkigenerator.util.CertificateTypeEnum;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.HashSet;
import java.util.List;

public class MainService {

	private static final Logger log = LoggerFactory.getLogger(MainService.class);
	
	private final CertificateService certificateService;
	private final Path installFolder;
	
	public MainService() {
		this(AppConstants.defaultOutputDir());
	}
	
	public MainService(Path installFolder) {
		this.certificateService = new CertificateService();
		this.installFolder = installFolder.toAbsolutePath().normalize();
	}
	
	public void generateCA(String commonName, String issuer) throws Exception {
		String commonNameFolder = Slugify.builder()
				.underscoreSeparator(true)
				.build()
				.slugify(commonName);
		
		boolean isRoot = StringUtils.isEmpty(issuer);
		
		X509Certificate issuerCertificate = null;
		KeyPair issuerKeyPair = null;
		if (!isRoot) {
			Path pathIssuer = Paths.get(
					installFolder.toString(),
					AppConstants.ROOT_CA_FOLDER,
					issuer,
					issuer + ".p12");
			
			if (Files.notExists(pathIssuer))
				throw new RuntimeException("File " + pathIssuer + " doesn't exist.");
			
			KeyStore keyStore = KeyStore.getInstance("PKCS12");
			try (InputStream is = Files.newInputStream(pathIssuer)) {
				keyStore.load(is, CertificateService.CACERTS_DEFAULT_PWD.toCharArray());
			}
			
			PrivateKey issuerPrivateKey = (PrivateKey) keyStore.getKey(
					CertificateService.KEYSTORE_DEFAULT_ALIAS,
					CertificateService.CACERTS_DEFAULT_PWD.toCharArray());
			
			issuerCertificate = (X509Certificate) keyStore.getCertificate(CertificateService.KEYSTORE_DEFAULT_ALIAS);
			issuerKeyPair = new KeyPair(issuerCertificate.getPublicKey(), issuerPrivateKey);
		}
		
		Path pathBase = Paths.get(installFolder.toString(), isRoot ? AppConstants.ROOT_CA_FOLDER : AppConstants.INTERMEDIATE_CA_FOLDER);
		Files.createDirectories(pathBase);
		
		Path pathFile = pathBase
				.resolve(commonNameFolder)
				.resolve(commonNameFolder + ".p12");
		
		if (Files.exists(pathFile))
			throw new RuntimeException("File " + pathFile + " already exists.");
		
		Files.createDirectories(pathFile.getParent());
		
		KeyPair keyPair = certificateService.generateKeyPair4096();
		
		CARequest requestRoot = CARequest.builder()
					.countryCode("BR")
					.organization("LOCALHOST")
					.organizationalUnit("EXAMPLE")
					.commonName(commonName)
					.expirationYears(20)
					.notAfter((!isRoot) ? issuerCertificate.getNotAfter().toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime() : null)
					.cpsPointerUri("http://example.com/cpsPointerUri.pdf")
					.crlDistributionPointUri("http://example.com/crlDistributionPointUri.crl")
					.build();
		
		X509Certificate certificate = certificateService.createCertificateAuthority(
				keyPair,
				(!isRoot) ? issuerKeyPair : keyPair,
				(!isRoot) ? issuerCertificate.getSubjectX500Principal() : null,
				requestRoot);
		certificateService.saveCertificateToFile(certificate, keyPair, pathFile);
		
		log.info("{} CA '{}' created successfully.", isRoot ? "Root" : "Intermediate", commonName);
	}
	
	public void generateIcpCnpj(String commonName, String issuer, boolean isRoot, String cnpj, String email,
			String personName, String personCpf, CertificateTypeEnum certType) throws Exception {
		String commonNameFolder = Slugify.builder()
				.underscoreSeparator(true)
				.build()
				.slugify(cnpj + "_" + commonName);
		
		Path pathIssuer = Paths.get(
				installFolder.toString(),
				isRoot ? AppConstants.ROOT_CA_FOLDER : AppConstants.INTERMEDIATE_CA_FOLDER,
				issuer,
				issuer + ".p12");
		
		if (Files.notExists(pathIssuer))
			throw new RuntimeException("File " + pathIssuer + " doesn't exist.");
		
		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		try (InputStream is = Files.newInputStream(pathIssuer)) {
			keyStore.load(is, CertificateService.CACERTS_DEFAULT_PWD.toCharArray());
		}
		
		PrivateKey issuerPrivateKey = (PrivateKey) keyStore.getKey(
				CertificateService.KEYSTORE_DEFAULT_ALIAS,
				CertificateService.CACERTS_DEFAULT_PWD.toCharArray());
		
		X509Certificate issuerCertificate = (X509Certificate) keyStore.getCertificate(CertificateService.KEYSTORE_DEFAULT_ALIAS); // root or intermediate
		KeyPair issuerKeyPair = new KeyPair(issuerCertificate.getPublicKey(), issuerPrivateKey);
		
		Path pathBase = Paths.get(installFolder.toString(), AppConstants.ICP_CNPJ_FOLDER);
		Files.createDirectories(pathBase);
		
		Path pathFile = pathBase
				.resolve(commonNameFolder)
				.resolve(commonNameFolder + ".p12");
		
		if (Files.exists(pathFile))
			throw new RuntimeException("File " + pathFile + " already exists.");
		
		Files.createDirectories(pathFile.getParent());
		
		KeyPair keyPair = certificateService.generateKeyPair2048();
		
		var requestIcpCnpj = ICPBrasilCNPJRequest.builder()
				.nome(commonName)
				.cnpj(cnpj)
				.email(email)
				.nomeResponsavel(personName)
				.cpfResponsavel(personCpf)
				.dataNascimentoResponsavel(LocalDate.of(1990, 1, 1))
				.certificateTypeEnum(certType)
				.notAfter(issuerCertificate.getNotAfter().toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime())
				.build();
		
		X509Certificate certificate = certificateService.createIcpBrasilCNPJ(
				keyPair,
				issuerKeyPair,
				issuerCertificate.getSubjectX500Principal(),
				requestIcpCnpj);
		certificateService.saveCertificateToFile(certificate, keyPair, pathFile);
		
		log.info("ICP-Brasil certificate created successfully for CNPJ '{}'.", requestIcpCnpj.getCnpj());
	}
	
	public void generateIcpCpf(String commonName, String issuer, boolean isRoot, String cpf, String email, CertificateTypeEnum certType) throws Exception {
		String commonNameFolder = Slugify.builder()
				.underscoreSeparator(true)
				.build()
				.slugify(cpf + "_" + commonName);
		
		Path pathIssuer = Paths.get(
				installFolder.toString(),
				isRoot ? AppConstants.ROOT_CA_FOLDER : AppConstants.INTERMEDIATE_CA_FOLDER,
				issuer,
				issuer + ".p12");
		
		if (Files.notExists(pathIssuer))
			throw new RuntimeException("File " + pathIssuer + " doesn't exist.");
		
		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		try (InputStream is = Files.newInputStream(pathIssuer)) {
			keyStore.load(is, CertificateService.CACERTS_DEFAULT_PWD.toCharArray());
		}
		
		PrivateKey issuerPrivateKey = (PrivateKey) keyStore.getKey(
				CertificateService.KEYSTORE_DEFAULT_ALIAS,
				CertificateService.CACERTS_DEFAULT_PWD.toCharArray());
		
		X509Certificate issuerCertificate = (X509Certificate) keyStore.getCertificate(CertificateService.KEYSTORE_DEFAULT_ALIAS); // root or intermediate
		KeyPair issuerKeyPair = new KeyPair(issuerCertificate.getPublicKey(), issuerPrivateKey);
		
		Path pathBase = Paths.get(installFolder.toString(), AppConstants.ICP_CPF_FOLDER);
		Files.createDirectories(pathBase);
		
		Path pathFile = pathBase
				.resolve(commonNameFolder)
				.resolve(commonNameFolder + ".p12");
		
		if (Files.exists(pathFile))
			throw new RuntimeException("File " + pathFile + " already exists.");
		
		Files.createDirectories(pathFile.getParent());
		
		KeyPair keyPair = certificateService.generateKeyPair2048();
		
		var requestIcpCpf = ICPBrasilCPFRequest.builder()
				.nome(commonName)
				.cpf(cpf)
				.email(email)
				.dataNascimento(LocalDate.of(1990, 1, 1))
				.certificateTypeEnum(certType)
				.notAfter(issuerCertificate.getNotAfter().toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime())
				.build();
		
		X509Certificate certificate = certificateService.createIcpBrasilCPF(
				keyPair,
				issuerKeyPair,
				issuerCertificate.getSubjectX500Principal(),
				requestIcpCpf);
		certificateService.saveCertificateToFile(certificate, keyPair, pathFile);
		
		log.info("ICP-Brasil certificate created successfully for CPF '{}'.", requestIcpCpf.getCpf());
	}
	
	public void generateWebsite(String commonName, String issuer, boolean isRoot, List<String> dnsNames, List<String> ipAddresses) throws Exception {
		String commonNameFolder = Slugify.builder()
				.underscoreSeparator(true)
				.build()
				.slugify("website_" + commonName);
		
		Path pathIssuer = Paths.get(
				installFolder.toString(),
				isRoot ? AppConstants.ROOT_CA_FOLDER : AppConstants.INTERMEDIATE_CA_FOLDER,
				issuer,
				issuer + ".p12");
		
		if (Files.notExists(pathIssuer))
			throw new RuntimeException("File " + pathIssuer + " doesn't exist.");
		
		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		try (InputStream is = Files.newInputStream(pathIssuer)) {
			keyStore.load(is, CertificateService.CACERTS_DEFAULT_PWD.toCharArray());
		}
		
		PrivateKey issuerPrivateKey = (PrivateKey) keyStore.getKey(
				CertificateService.KEYSTORE_DEFAULT_ALIAS,
				CertificateService.CACERTS_DEFAULT_PWD.toCharArray());
		
		X509Certificate issuerCertificate = (X509Certificate) keyStore.getCertificate(CertificateService.KEYSTORE_DEFAULT_ALIAS); // root or intermediate
		KeyPair issuerKeyPair = new KeyPair(issuerCertificate.getPublicKey(), issuerPrivateKey);
		
		Path pathBase = Paths.get(installFolder.toString(), AppConstants.WEBSITE_FOLDER);
		Files.createDirectories(pathBase);
		
		Path pathFile = pathBase
				.resolve(commonNameFolder)
				.resolve(commonNameFolder + ".p12");
		
		if (Files.exists(pathFile))
			throw new RuntimeException("File " + pathFile + " already exists.");
		
		Files.createDirectories(pathFile.getParent());
		
		KeyPair keyPair = certificateService.generateKeyPair2048();
		
		var requestWebsite = WebsiteRequest.builder()
				.commonName(commonName)
				.dnsNames(dnsNames != null ? new HashSet<>(dnsNames) : new HashSet<>())
				.ipAddresses(ipAddresses != null ? new HashSet<>(ipAddresses) : new HashSet<>())
				.notAfter(issuerCertificate.getNotAfter().toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime())
				.build();
		
		X509Certificate certificate = certificateService.createWebsiteCertificate(
				keyPair,
				issuerKeyPair,
				issuerCertificate.getSubjectX500Principal(),
				requestWebsite);
		certificateService.saveCertificateToFile(certificate, keyPair, pathFile);
		
		log.info("Website certificate created successfully for '{}'.", commonName);
	}

}
