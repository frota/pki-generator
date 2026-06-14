package io.github.frota.pkigenerator.service;

import io.github.frota.pkigenerator.model.CARequest;
import io.github.frota.pkigenerator.model.ICPBrasilCNPJRequest;
import io.github.frota.pkigenerator.model.ICPBrasilCPFRequest;
import io.github.frota.pkigenerator.model.WebsiteRequest;
import io.github.frota.pkigenerator.util.CertificateTypeEnum;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.time.DurationFormatUtils;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStrictStyle;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.RSAKeyGenParameterSpec;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

public class CertificateService {

	private static final Logger log = LoggerFactory.getLogger(CertificateService.class);
	
	public static final String CACERTS_DEFAULT_PWD = "changeit";
	public static final String KEYSTORE_DEFAULT_ALIAS = "1";
	
	private static final String BC_PROVIDER = org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME;
	private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("ddMMyyyy");
	private static final SecureRandom SECURE_RANDOM = new SecureRandom();
	
	public CertificateService() {}
	
	public X509Certificate createCertificateAuthority(KeyPair keyPair, KeyPair singerKeyPair, X500Principal issuer, CARequest request)
			throws IOException, NoSuchAlgorithmException, OperatorCreationException, CertificateException {
		// TODO Validar request
		
		X500Name name = new X500NameBuilder(BCStrictStyle.INSTANCE)
				.addRDN(BCStyle.C, new DERUTF8String(request.getCountryCode()))
				.addRDN(BCStyle.O, new DERUTF8String(request.getOrganization()))
				.addRDN(BCStyle.OU, new DERUTF8String(request.getOrganizationalUnit()))
				.addRDN(BCStyle.CN, new DERUTF8String(request.getCommonName()))
				.build();
		
		X500Principal subject = new X500Principal(name.getEncoded());
		BigInteger serialNum = generatePositiveSerialNumber();
		LocalDateTime notBefore = LocalDateTime.now();
		LocalDateTime notAfter = notBefore.plusYears(request.getExpirationYears());
		
		if (request.getNotAfter() != null && request.getNotAfter().isBefore(notAfter)) {
			notAfter = request.getNotAfter();
		}
		
		X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
				(issuer != null) ? issuer : subject, // issuer
				serialNum,
				Date.from(notBefore.atZone(ZoneId.systemDefault()).toInstant()),
				Date.from(notAfter.atZone(ZoneId.systemDefault()).toInstant()),
				subject, // subject
				keyPair.getPublic());
		
		Duration diff = Duration.between(notBefore, notAfter);
		String pretty = DurationFormatUtils.formatDuration(diff.toMillis(), "d 'days' HH:mm:ss");
		log.info("Validity period: {}", pretty);
		
		// Add Extensions
		JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
		
		final String cpsPointerUri = request.getCpsPointerUri();
		if (StringUtils.isNotBlank(cpsPointerUri)) {
			final ASN1EncodableVector policyQualifySeq = new ASN1EncodableVector();
			policyQualifySeq.add(new PolicyQualifierInfo(cpsPointerUri.trim()));
			PolicyInformation policyInfo = new PolicyInformation(new ASN1ObjectIdentifier("2.16.76.1.1.0"), new DERSequence(policyQualifySeq));
			final ASN1EncodableVector policySeq = new ASN1EncodableVector();
			policySeq.add(policyInfo);
			
			certBuilder.addExtension(Extension.certificatePolicies, false, new DERSequence(policySeq)); // 2.5.29.32
		}
		
		final String crlDistributionPointUri = request.getCrlDistributionPointUri();
		if (StringUtils.isNotBlank(crlDistributionPointUri)) {
			GeneralName generalName = new GeneralName(GeneralName.uniformResourceIdentifier, crlDistributionPointUri.trim());
			DistributionPointName distPointName = new DistributionPointName(new GeneralNames(generalName));
			final DistributionPoint[] distPoints = { new DistributionPoint(distPointName, null, null) };
			
			certBuilder.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(distPoints)); // 2.5.29.31
		}
		
		certBuilder
				.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(singerKeyPair.getPublic())) // 2.5.29.35
				.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(keyPair.getPublic())) // 2.5.29.14
				.addExtension(Extension.basicConstraints, true, new BasicConstraints(true)) // 2.5.29.19: a BasicConstraints to mark root certificate as CA certificate
				.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign)); // 2.5.29.15
		
		ContentSigner signer = new JcaContentSignerBuilder("SHA512withRSA")
				.setProvider(BC_PROVIDER)
				.build(singerKeyPair.getPrivate());
		
		JcaX509CertificateConverter converter = new JcaX509CertificateConverter()
				.setProvider(BC_PROVIDER);
		return converter.getCertificate(certBuilder.build(signer));
	}
	
	public X509Certificate createIcpBrasilCNPJ(KeyPair keyPair, KeyPair singerKeyPair, X500Principal issuer, ICPBrasilCNPJRequest request)
			throws IOException, NoSuchAlgorithmException, OperatorCreationException, CertificateException {
		// TODO Validar e formatar nome
		
		final String nome = request.getNome();
		final String cnpj = request.getCnpj();
		final String commonName = nome + ":" + cnpj;
		final CertificateTypeEnum certType = request.getCertificateTypeEnum() != null ? request.getCertificateTypeEnum() : CertificateTypeEnum.A1;
		
		X500Name name = new X500NameBuilder(BCStrictStyle.INSTANCE)
				.addRDN(BCStyle.C, new DERUTF8String("BR"))
				.addRDN(BCStyle.O, new DERUTF8String("ICP-Brasil"))
				.addRDN(BCStyle.OU, new DERUTF8String("CERTIFICADO DIGITAL"))
				.addRDN(BCStyle.OU, new DERUTF8String("Certificado Digital PJ " + certType.name()))
				.addRDN(BCStyle.OU, new DERUTF8String("45616309000149"))
				.addRDN(BCStyle.OU, new DERUTF8String("AC SyngularID Multipla"))
				.addRDN(BCStyle.CN, new DERUTF8String(commonName))
				.build();
		
		X500Principal subject = new X500Principal(name.getEncoded());
		BigInteger serialNum = generatePositiveSerialNumber();
		LocalDateTime notBefore = LocalDateTime.now();
		LocalDateTime notAfter = notBefore.plusYears(3);
		
		if (request.getNotAfter() != null && request.getNotAfter().isBefore(notAfter)) {
			notAfter = request.getNotAfter();
		}
		
		X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
				issuer, // issuer
				serialNum,
				Date.from(notBefore.atZone(ZoneId.systemDefault()).toInstant()),
				Date.from(notAfter.atZone(ZoneId.systemDefault()).toInstant()),
				subject, // subject
				keyPair.getPublic());
		
		final String dataNascimentoResponsavel = request.getDataNascimentoResponsavel().format(DATE_FORMATTER);
		final String cpfResponsavel = request.getCpfResponsavel();
		final String email = request.getEmail();
		
		// NOME_RESPONSAVEL
		final String nomeResponsavel = StringUtils.isEmpty(request.getNomeResponsavel()) ? nome : request.getNomeResponsavel();
		// DATA_NASC(8) + CPF(11) + PIS/PASEP(11) + RG(15) + ORGEXP+UF(10)
		final String dadosResponsavel = dataNascimentoResponsavel + cpfResponsavel + "00000000000" + "000000000000000" + "";
		// CEI_INSS(12)
		final String dadosCeiInss = "000000000000";
		
		// Add Extensions
		JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
		
		ASN1EncodableVector altNames = new ASN1EncodableVector();
		altNames.add(new GeneralName(GeneralName.otherName,
				new DERSequence(new ASN1Encodable[] { new ASN1ObjectIdentifier("2.16.76.1.3.2"),
						new DERTaggedObject(true, 0, new DEROctetString(nomeResponsavel.getBytes())) })));
		altNames.add(new GeneralName(GeneralName.otherName,
				new DERSequence(new ASN1Encodable[] { new ASN1ObjectIdentifier("2.16.76.1.3.3"),
						new DERTaggedObject(true, 0, new DEROctetString(cnpj.getBytes())) })));
		altNames.add(new GeneralName(GeneralName.otherName,
				new DERSequence(new ASN1Encodable[] { new ASN1ObjectIdentifier("2.16.76.1.3.4"),
						new DERTaggedObject(true, 0, new DEROctetString(dadosResponsavel.getBytes())) })));
		altNames.add(new GeneralName(GeneralName.otherName,
				new DERSequence(new ASN1Encodable[] { new ASN1ObjectIdentifier("2.16.76.1.3.7"),
						new DERTaggedObject(true, 0, new DEROctetString(dadosCeiInss.getBytes())) })));
		altNames.add(new GeneralName(GeneralName.otherName,
				new DERSequence(new ASN1Encodable[] { new ASN1ObjectIdentifier("2.16.76.1.3.8"),
						new DERTaggedObject(true, 0, new DEROctetString(nome.getBytes())) })));
		if (StringUtils.isNotEmpty(email))
			altNames.add(new GeneralName(GeneralName.rfc822Name, email));
		
		final ASN1EncodableVector policyQualifiers = new ASN1EncodableVector();
		policyQualifiers.add(new PolicyQualifierInfo(PolicyQualifierId.id_qt_cps, new DERIA5String("http://icp-brasil.validcertificadora.com.br/ac-validsslev/dpcacvalidsslev.pdf")));
		PolicyInformation policyInfo1 = new PolicyInformation(new ASN1ObjectIdentifier(certType.getPolicyOid()), new DERSequence(policyQualifiers));
		PolicyInformation policyInfo2 = new PolicyInformation(new ASN1ObjectIdentifier("2.23.140.1.1"));
		final ASN1EncodableVector policies = new ASN1EncodableVector();
		policies.add(policyInfo1);
		policies.add(policyInfo2);
		
		GeneralName generalName1 = new GeneralName(GeneralName.uniformResourceIdentifier, "http://icp-brasil.validcertificadora.com.br/ac-validsslev/lcr-ac-validsslev.crl");
		DistributionPointName distPointName1 = new DistributionPointName(new GeneralNames(generalName1));
		GeneralName generalName2 = new GeneralName(GeneralName.uniformResourceIdentifier, "http://icp-brasil2.validcertificadora.com.br/ac-validsslev/lcr-ac-validsslev.crl");
		DistributionPointName distPointName2 = new DistributionPointName(new GeneralNames(generalName2));
		final DistributionPoint[] distPoints = {
				new DistributionPoint(distPointName1, null, null),
				new DistributionPoint(distPointName2, null, null) };
		
		AuthorityInformationAccess authorityInfoAccess = new AuthorityInformationAccess(new AccessDescription[] {
				new AccessDescription(AccessDescription.id_ad_caIssuers,
						new GeneralName(GeneralName.uniformResourceIdentifier, "http://icp-brasil.validcertificadora.com.br/ac-validsslev/ac-validsslev.p7b")),
				new AccessDescription(AccessDescription.id_ad_ocsp,
						new GeneralName(GeneralName.uniformResourceIdentifier, "http://ocspv10.validcertificadora.com.br")) });
		
		certBuilder
				.addExtension(Extension.subjectAlternativeName, false, new DERSequence(altNames))
				.addExtension(Extension.basicConstraints, false, new BasicConstraints(false)) // 2.5.29.19
				.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(singerKeyPair.getPublic())) // 2.5.29.35
				.addExtension(Extension.certificatePolicies, false, new DERSequence(policies))
				.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(distPoints))
				.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation | KeyUsage.keyEncipherment)) // 2.5.29.15
				.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(new KeyPurposeId[] { KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_emailProtection, KeyPurposeId.id_kp_serverAuth }))
				.addExtension(Extension.authorityInfoAccess, false, authorityInfoAccess)
				.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(keyPair.getPublic())); // 2.5.29.14
		
		ContentSigner signer = new JcaContentSignerBuilder("SHA512withRSA")
				.setProvider(BC_PROVIDER)
				.build(singerKeyPair.getPrivate());
		
		JcaX509CertificateConverter converter = new JcaX509CertificateConverter()
				.setProvider(BC_PROVIDER);
		return converter.getCertificate(certBuilder.build(signer));
	}
	
	public X509Certificate createIcpBrasilCPF(KeyPair keyPair, KeyPair singerKeyPair, X500Principal issuer, ICPBrasilCPFRequest request)
			throws IOException, NoSuchAlgorithmException, OperatorCreationException, CertificateException {
		// TODO Validar e formatar nome
		
		final String nome = request.getNome();
		final String cpf = request.getCpf();
		final String commonName = nome + ":" + cpf;
		final CertificateTypeEnum certType = request.getCertificateTypeEnum() != null ? request.getCertificateTypeEnum() : CertificateTypeEnum.A1;
		
		X500Name name = new X500NameBuilder(BCStrictStyle.INSTANCE)
				.addRDN(BCStyle.C, new DERUTF8String("BR"))
				.addRDN(BCStyle.O, new DERUTF8String("ICP-Brasil"))
				.addRDN(BCStyle.OU, new DERUTF8String("Presencial"))
				.addRDN(BCStyle.OU, new DERUTF8String("07267479000176"))
				.addRDN(BCStyle.OU, new DERUTF8String("Secretaria da Receita Federal do Brasil - RFB"))
				.addRDN(BCStyle.OU, new DERUTF8String("RFB e-CPF " + certType.name()))
				.addRDN(BCStyle.OU, new DERUTF8String("(em branco)"))
				.addRDN(BCStyle.CN, new DERUTF8String(commonName))
				.build();
		
		X500Principal subject = new X500Principal(name.getEncoded());
		BigInteger serialNum = generatePositiveSerialNumber();
		LocalDateTime notBefore = LocalDateTime.now();
		LocalDateTime notAfter = notBefore.plusYears(3);
		
		if (request.getNotAfter() != null && request.getNotAfter().isBefore(notAfter)) {
			notAfter = request.getNotAfter();
		}
		
		X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
				issuer, // issuer
				serialNum,
				Date.from(notBefore.atZone(ZoneId.systemDefault()).toInstant()),
				Date.from(notAfter.atZone(ZoneId.systemDefault()).toInstant()),
				subject, // subject
				keyPair.getPublic());
		
		final String dataNascimento = request.getDataNascimento().format(DATE_FORMATTER);
		final String email = request.getEmail();
		
		// DATA_NASC(8) + CPF(11) + PIS/PASEP(11) + RG(15) + ORGEXP+UF(10)
		final String dadosPessoais = dataNascimento + cpf + "00000000000" + "000000000000000" + "";
		// CEI_INSS(12)
		final String dadosCeiIness = "000000000000";
		// TITULO_ELE(12) + ZONA(3) + SECAO(4) + MUNIC+UF(22)
		final String dadosTituloEleitor = "000000000000" + "000" + "0000" + "";
		
		// Add Extensions
		JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
		
		ASN1EncodableVector altNames = new ASN1EncodableVector();
		altNames.add(new GeneralName(GeneralName.otherName,
				new DERSequence(new ASN1Encodable[] { new ASN1ObjectIdentifier("2.16.76.1.3.1"), new DERTaggedObject(true, 0, new DEROctetString(dadosPessoais.getBytes())) })));
		altNames.add(new GeneralName(GeneralName.otherName,
				new DERSequence(new ASN1Encodable[] { new ASN1ObjectIdentifier("2.16.76.1.3.6"), new DERTaggedObject(true, 0, new DEROctetString(dadosCeiIness.getBytes())) })));
		altNames.add(new GeneralName(GeneralName.otherName,
				new DERSequence(new ASN1Encodable[] { new ASN1ObjectIdentifier("2.16.76.1.3.5"), new DERTaggedObject(true, 0, new DEROctetString(dadosTituloEleitor.getBytes())) })));
		if (StringUtils.isNotEmpty(email))
			altNames.add(new GeneralName(GeneralName.rfc822Name, email));
		
		final ASN1EncodableVector policyQualifiers = new ASN1EncodableVector();
		policyQualifiers.add(new PolicyQualifierInfo(PolicyQualifierId.id_qt_cps, new DERIA5String("http://icp-brasil.certisign.com.br/repositorio/dpc/AC_Certisign_RFB/DPC_AC_Certisign_RFB.pdf")));
		PolicyInformation policyInfo = new PolicyInformation(new ASN1ObjectIdentifier(certType.getPolicyOid()), new DERSequence(policyQualifiers));
		final ASN1EncodableVector policies = new ASN1EncodableVector();
		policies.add(policyInfo);
		
		GeneralName generalName1 = new GeneralName(GeneralName.uniformResourceIdentifier, "http://icp-brasil.certisign.com.br/repositorio/lcr/ACCertisignRFBG5/LatestCRL.crl");
		DistributionPointName distPointName1 = new DistributionPointName(new GeneralNames(generalName1));
		GeneralName generalName2 = new GeneralName(GeneralName.uniformResourceIdentifier, "http://icp-brasil.outralcr.com.br/repositorio/lcr/ACCertisignRFBG5/LatestCRL.crl");
		DistributionPointName distPointName2 = new DistributionPointName(new GeneralNames(generalName2));
		final DistributionPoint[] distPoints = {
				new DistributionPoint(distPointName1, null, null),
				new DistributionPoint(distPointName2, null, null) };
		
		AuthorityInformationAccess authorityInfoAccess = new AuthorityInformationAccess(new AccessDescription[] {
				new AccessDescription(AccessDescription.id_ad_caIssuers,
						new GeneralName(GeneralName.uniformResourceIdentifier, "http://icp-brasil.certisign.com.br/repositorio/certificados/AC_Certisign_RFB_G5.p7c")),
				new AccessDescription(AccessDescription.id_ad_ocsp,
						new GeneralName(GeneralName.uniformResourceIdentifier, "http://ocsp-ac-certisign-rfb.certisign.com.br")) });
		
		certBuilder
				.addExtension(Extension.subjectAlternativeName, false, new DERSequence(altNames)) // 2.5.29.17
				.addExtension(Extension.basicConstraints, false, new BasicConstraints(false)) // 2.5.29.19
				.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(singerKeyPair.getPublic())) // 2.5.29.35
				.addExtension(Extension.certificatePolicies, false, new DERSequence(policies)) // 2.5.29.32
				.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(distPoints)) // 2.5.29.31
				.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation | KeyUsage.keyEncipherment)) // 2.5.29.15
				.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(new KeyPurposeId[] { KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_emailProtection })) // 2.5.29.37
				.addExtension(Extension.authorityInfoAccess, false, authorityInfoAccess) // 1.3.6.1.5.5.7.1.1
				.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(keyPair.getPublic())); // 2.5.29.14
		
		ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
				.setProvider(BC_PROVIDER)
				.build(singerKeyPair.getPrivate());
		
		JcaX509CertificateConverter converter = new JcaX509CertificateConverter()
				.setProvider(BC_PROVIDER);
		return converter.getCertificate(certBuilder.build(signer));
	}
	
	public X509Certificate createWebsiteCertificate(KeyPair keyPair, KeyPair singerKeyPair, X500Principal issuer, WebsiteRequest request)
			throws IOException, NoSuchAlgorithmException, OperatorCreationException, CertificateException {
		// TODO Validar e formatar nome
		
		final String commonName = request.getCommonName();
		
		X500Name name = new X500NameBuilder(BCStrictStyle.INSTANCE)
				.addRDN(BCStyle.CN, new DERUTF8String(commonName))
				.build();
		
		X500Principal subject = new X500Principal(name.getEncoded());
		BigInteger serialNum = generatePositiveSerialNumber();
		LocalDateTime notBefore = LocalDateTime.now();
		LocalDateTime notAfter = notBefore.plusYears(3);
		
		if (request.getNotAfter() != null && request.getNotAfter().isBefore(notAfter)) {
			notAfter = request.getNotAfter();
		}
		
		X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
				issuer, // issuer
				serialNum,
				Date.from(notBefore.atZone(ZoneId.systemDefault()).toInstant()),
				Date.from(notAfter.atZone(ZoneId.systemDefault()).toInstant()),
				subject, // subject
				keyPair.getPublic());
		
		// Add Extensions
		JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
		
		ASN1EncodableVector altNames = new ASN1EncodableVector();
		for (String dns : request.getDnsNames()) {
			if (StringUtils.isNotBlank(dns)) {
				altNames.add(new GeneralName(GeneralName.dNSName, dns));
			}
		}
		for (String ip : request.getIpAddresses()) {
			if (StringUtils.isNotBlank(ip)) {
				altNames.add(new GeneralName(GeneralName.iPAddress, ip));
			}
		}
		
		PolicyInformation policyInfo = new PolicyInformation(new ASN1ObjectIdentifier("2.23.140.1.1"));
		final ASN1EncodableVector policies = new ASN1EncodableVector();
		policies.add(policyInfo);
		
		GeneralName generalName = new GeneralName(GeneralName.uniformResourceIdentifier, "http://example.com/example.crl");
		DistributionPointName distPointName = new DistributionPointName(new GeneralNames(generalName));
		final DistributionPoint[] distPoints = {
				new DistributionPoint(distPointName, null, null) };
		
		AuthorityInformationAccess authorityInfoAccess = new AuthorityInformationAccess(new AccessDescription[] {
				new AccessDescription(AccessDescription.id_ad_ocsp, // 1.3.6.1.5.5.7.48.1
						new GeneralName(GeneralName.uniformResourceIdentifier, "http://example.com/")),
				new AccessDescription(AccessDescription.id_ad_caIssuers, // 1.3.6.1.5.5.7.48.2
						new GeneralName(GeneralName.uniformResourceIdentifier, "http://example.com/")) });
		
		certBuilder
				.addExtension(Extension.subjectAlternativeName, false, new DERSequence(altNames))
				.addExtension(Extension.basicConstraints, true, new BasicConstraints(false)) // 2.5.29.19
				.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(singerKeyPair.getPublic())) // 2.5.29.35
				.addExtension(Extension.certificatePolicies, false, new DERSequence(policies))
				.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(distPoints))
				.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature)) // 2.5.29.15
				.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(new KeyPurposeId[] { KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_serverAuth }))
				.addExtension(Extension.authorityInfoAccess, false, authorityInfoAccess)
				.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(keyPair.getPublic())); // 2.5.29.14
		
		byte[] sctList = new byte[] { 0x00 }; // minimal placeholder
		DEROctetString sctExtensionValue = new DEROctetString(sctList);
		
		certBuilder
				.addExtension(new ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2"), false, sctExtensionValue); // SCTs
		
		ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
				.setProvider(BC_PROVIDER)
				.build(singerKeyPair.getPrivate());
		
		JcaX509CertificateConverter converter = new JcaX509CertificateConverter()
				.setProvider(BC_PROVIDER);
		return converter.getCertificate(certBuilder.build(signer));
	}
	
	public X509Certificate createClonedCertificate(X509Certificate sourceCertificate, KeyPair keyPair, KeyPair singerKeyPair,
			X500Principal issuer, LocalDateTime issuerNotAfter)
			throws IOException, NoSuchAlgorithmException, OperatorCreationException, CertificateException {
		LocalDateTime sourceNotBefore = sourceCertificate.getNotBefore().toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime();
		LocalDateTime notBefore = sourceNotBefore;
		LocalDateTime sourceNotAfter = sourceCertificate.getNotAfter().toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime();
		LocalDateTime notAfter = sourceNotAfter;
		
		if (issuerNotAfter != null && issuerNotAfter.isBefore(notAfter)) {
			notAfter = issuerNotAfter;
		}
		
//		if (!notAfter.isAfter(notBefore)) {
//			throw new CertificateException("Source certificate or issuer certificate is already expired.");
//		}
		
		X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
				issuer,
				generatePositiveSerialNumber(),
				Date.from(notBefore.atZone(ZoneId.systemDefault()).toInstant()),
				Date.from(notAfter.atZone(ZoneId.systemDefault()).toInstant()),
				sourceCertificate.getSubjectX500Principal(),
				keyPair.getPublic());
		
		copyCloneableExtensions(sourceCertificate, certBuilder);
		
		JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
		certBuilder
				.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(singerKeyPair.getPublic()))
				.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(keyPair.getPublic()));
		
		ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
				.setProvider(BC_PROVIDER)
				.build(singerKeyPair.getPrivate());
		
		JcaX509CertificateConverter converter = new JcaX509CertificateConverter()
				.setProvider(BC_PROVIDER);
		return converter.getCertificate(certBuilder.build(signer));
	}
	
	public void saveCertificateToFile(Certificate[] chain, KeyPair keyPair, Path output)
			throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		keyStore.load(null, null);
		keyStore.setKeyEntry(KEYSTORE_DEFAULT_ALIAS, keyPair.getPrivate(), CACERTS_DEFAULT_PWD.toCharArray(), chain);
		try (OutputStream os = Files.newOutputStream(output)) {
			keyStore.store(os, CACERTS_DEFAULT_PWD.toCharArray());
		}
	}
	
	public KeyPair generateKeyPair2048() {
		return generateKeyPair(2048);
	}
	
	public KeyPair generateKeyPair4096() {
		return generateKeyPair(4096);
	}
	
	private KeyPair generateKeyPair(int keysize) {
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", BC_PROVIDER);
			keyPairGenerator.initialize(new RSAKeyGenParameterSpec(keysize, RSAKeyGenParameterSpec.F4));
			return keyPairGenerator.generateKeyPair();
		} catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
	}
	
	private void copyCloneableExtensions(X509Certificate sourceCertificate, X509v3CertificateBuilder certBuilder) throws IOException {
		Set<String> criticalExtensionOids = nullToEmpty(sourceCertificate.getCriticalExtensionOIDs());
		Set<String> nonCriticalExtensionOids = nullToEmpty(sourceCertificate.getNonCriticalExtensionOIDs());
		Set<String> extensionOids = new HashSet<>();
		extensionOids.addAll(criticalExtensionOids);
		extensionOids.addAll(nonCriticalExtensionOids);
		
		for (String oid : extensionOids) {
			if (isRegeneratedExtension(oid)) {
				continue;
			}
			
			byte[] extensionValue = sourceCertificate.getExtensionValue(oid);
			if (extensionValue == null) {
				continue;
			}
			
			ASN1OctetString octets = ASN1OctetString.getInstance(ASN1Primitive.fromByteArray(extensionValue));
			certBuilder.addExtension(
					new ASN1ObjectIdentifier(oid),
					criticalExtensionOids.contains(oid),
					octets.getOctets());
		}
	}
	
	private Set<String> nullToEmpty(Collection<String> values) {
		return values == null ? Set.of() : new HashSet<>(values);
	}
	
	private boolean isRegeneratedExtension(String oid) {
		return Extension.authorityKeyIdentifier.getId().equals(oid)
				|| Extension.subjectKeyIdentifier.getId().equals(oid);
	}
	
	private BigInteger generatePositiveSerialNumber() {
		return new BigInteger(159, SECURE_RANDOM).setBit(159);
	}

}
