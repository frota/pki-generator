package io.github.frota.pkigenerator.service;

import com.github.slugify.Slugify;
import io.github.frota.pkigenerator.model.CARequest;
import io.github.frota.pkigenerator.model.ICPBrasilCNPJRequest;
import io.github.frota.pkigenerator.model.ICPBrasilCPFRequest;
import io.github.frota.pkigenerator.model.IssuerMaterial;
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
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.HashSet;
import java.util.List;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

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
		
		IssuerMaterial issuerMaterial = null;
		if (!isRoot) {
			Path pathIssuer = Paths.get(
					installFolder.toString(),
					AppConstants.ROOT_CA_FOLDER,
					issuer,
					issuer + ".p12");
			
			if (Files.notExists(pathIssuer))
				throw new RuntimeException("File " + pathIssuer + " doesn't exist.");
			
			issuerMaterial = loadIssuerMaterial(pathIssuer);
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
					.notAfter((!isRoot) ? issuerMaterial.issuerCertificate().getNotAfter().toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime() : null)
					.cpsPointerUri("http://example.com/cpsPointerUri.pdf")
					.crlDistributionPointUri("http://example.com/crlDistributionPointUri.crl")
					.build();
		
		X509Certificate certificate = certificateService.createCertificateAuthority(
				keyPair,
				(!isRoot) ? issuerMaterial.issuerKeyPair() : keyPair,
				(!isRoot) ? issuerMaterial.issuerCertificate().getSubjectX500Principal() : null,
				requestRoot);
		
		Certificate[] chain = isRoot
				? new Certificate[] { certificate }
				: prependCertificate(certificate, issuerMaterial.issuerChain());
		certificateService.saveCertificateToFile(chain, keyPair, pathFile);
		
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
		
		IssuerMaterial issuerMaterial = loadIssuerMaterial(pathIssuer);
		
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
				.notAfter(issuerMaterial.issuerCertificate().getNotAfter().toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime())
				.build();
		
		X509Certificate certificate = certificateService.createIcpBrasilCNPJ(
				keyPair,
				issuerMaterial.issuerKeyPair(),
				issuerMaterial.issuerCertificate().getSubjectX500Principal(),
				requestIcpCnpj);
		certificateService.saveCertificateToFile(prependCertificate(certificate, issuerMaterial.issuerChain()), keyPair, pathFile);
		
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
		
		IssuerMaterial issuerMaterial = loadIssuerMaterial(pathIssuer);
		
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
				.notAfter(issuerMaterial.issuerCertificate().getNotAfter().toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime())
				.build();
		
		X509Certificate certificate = certificateService.createIcpBrasilCPF(
				keyPair,
				issuerMaterial.issuerKeyPair(),
				issuerMaterial.issuerCertificate().getSubjectX500Principal(),
				requestIcpCpf);
		certificateService.saveCertificateToFile(prependCertificate(certificate, issuerMaterial.issuerChain()), keyPair, pathFile);
		
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
		
		IssuerMaterial issuerMaterial = loadIssuerMaterial(pathIssuer);
		
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
				.notAfter(issuerMaterial.issuerCertificate().getNotAfter().toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime())
				.build();
		
		X509Certificate certificate = certificateService.createWebsiteCertificate(
				keyPair,
				issuerMaterial.issuerKeyPair(),
				issuerMaterial.issuerCertificate().getSubjectX500Principal(),
				requestWebsite);
		certificateService.saveCertificateToFile(prependCertificate(certificate, issuerMaterial.issuerChain()), keyPair, pathFile);
		
		log.info("Website certificate created successfully for '{}'.", commonName);
	}
	
	public void cloneCertificate(Path sourceCertificatePath, String issuer, boolean isRoot, String name) throws Exception {
		X509Certificate sourceCertificate = loadCertificate(sourceCertificatePath);
		
		String outputName = StringUtils.defaultIfBlank(name, getCommonName(sourceCertificate));
		if (StringUtils.isBlank(outputName)) {
			outputName = "serial_" + sourceCertificate.getSerialNumber().toString(16);
		}
		
		String outputFolder = Slugify.builder()
				.underscoreSeparator(true)
				.build()
				.slugify("clone_" + outputName);
		
		Path pathIssuer = Paths.get(
				installFolder.toString(),
				isRoot ? AppConstants.ROOT_CA_FOLDER : AppConstants.INTERMEDIATE_CA_FOLDER,
				issuer,
				issuer + ".p12");
		
		if (Files.notExists(pathIssuer))
			throw new RuntimeException("File " + pathIssuer + " doesn't exist.");
		
		IssuerMaterial issuerMaterial = loadIssuerMaterial(pathIssuer);
		
		Path pathBase = Paths.get(installFolder.toString(), AppConstants.CLONED_FOLDER);
		Files.createDirectories(pathBase);
		
		Path pathFile = pathBase
				.resolve(outputFolder)
				.resolve(outputFolder + ".p12");
		
		if (Files.exists(pathFile))
			throw new RuntimeException("File " + pathFile + " already exists.");
		
		Files.createDirectories(pathFile.getParent());
		
		KeyPair keyPair = certificateService.generateKeyPair2048();
		
		X509Certificate certificate = certificateService.createClonedCertificate(
				sourceCertificate,
				keyPair,
				issuerMaterial.issuerKeyPair(),
				issuerMaterial.issuerCertificate().getSubjectX500Principal(),
				issuerMaterial.issuerCertificate().getNotAfter().toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime());
		certificateService.saveCertificateToFile(prependCertificate(certificate, issuerMaterial.issuerChain()), keyPair, pathFile);
		
		log.info("Certificate cloned successfully from '{}' to '{}'.", sourceCertificatePath, pathFile);
	}
	
	private IssuerMaterial loadIssuerMaterial(Path pathIssuer) throws Exception {
		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		try (InputStream is = Files.newInputStream(pathIssuer)) {
			keyStore.load(is, CertificateService.CACERTS_DEFAULT_PWD.toCharArray());
		}
		
		PrivateKey issuerPrivateKey = (PrivateKey) keyStore.getKey(
				CertificateService.KEYSTORE_DEFAULT_ALIAS,
				CertificateService.CACERTS_DEFAULT_PWD.toCharArray());
		if (issuerPrivateKey == null) {
			throw new RuntimeException("Private key not found in " + pathIssuer);
		}
		
		Certificate[] rawChain = keyStore.getCertificateChain(CertificateService.KEYSTORE_DEFAULT_ALIAS);
		X509Certificate[] issuerChain;
		if (rawChain == null || rawChain.length == 0) {
			X509Certificate issuerCertificate = (X509Certificate) keyStore.getCertificate(CertificateService.KEYSTORE_DEFAULT_ALIAS);
			if (issuerCertificate == null) {
				throw new RuntimeException("Certificate not found in " + pathIssuer);
			}
			issuerChain = new X509Certificate[] { issuerCertificate };
		} else {
			issuerChain = new X509Certificate[rawChain.length];
			for (int i = 0; i < rawChain.length; i++) {
				issuerChain[i] = (X509Certificate) rawChain[i];
			}
		}
		
		X509Certificate issuerCertificate = issuerChain[0];
		KeyPair issuerKeyPair = new KeyPair(issuerCertificate.getPublicKey(), issuerPrivateKey);
		return new IssuerMaterial(issuerCertificate, issuerKeyPair, issuerChain);
	}
	
	private Certificate[] prependCertificate(X509Certificate certificate, X509Certificate[] issuerChain) {
		Certificate[] chain = new Certificate[issuerChain.length + 1];
		chain[0] = certificate;
		System.arraycopy(issuerChain, 0, chain, 1, issuerChain.length);
		return chain;
	}
	
	private X509Certificate loadCertificate(Path sourceCertificatePath) throws Exception {
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		try (InputStream is = Files.newInputStream(sourceCertificatePath)) {
			return (X509Certificate) certificateFactory.generateCertificate(is);
		}
	}
	
	private String getCommonName(X509Certificate certificate) {
		try {
			LdapName ldapName = new LdapName(certificate.getSubjectX500Principal().getName());
			for (Rdn rdn : ldapName.getRdns()) {
				if ("CN".equalsIgnoreCase(rdn.getType())) {
					return rdn.getValue().toString();
				}
			}
		} catch (Exception ex) {
			log.warn("Could not extract common name from source certificate subject.", ex);
		}
		return null;
	}

}
