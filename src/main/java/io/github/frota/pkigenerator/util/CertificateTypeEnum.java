package io.github.frota.pkigenerator.util;

public enum CertificateTypeEnum {

	A1("2.16.76.1.2.1.110"), // PC A1 da AC VALID SSL EV
	A3("2.16.76.1.2.3.6");   // PC A3 da AC CERTISIGN RFB
	
	private final String policyOid;
	
	CertificateTypeEnum(String policyOid) {
		this.policyOid = policyOid;
	}
	
	public String getPolicyOid() {
		return policyOid;
	}

}
