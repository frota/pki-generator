package io.github.frota.pkigenerator.util;

import org.apache.commons.validator.routines.DomainValidator;
import org.apache.commons.validator.routines.InetAddressValidator;

public final class HostNameUtils {

	private static final DomainValidator DOMAIN_VALIDATOR = DomainValidator.getInstance(true);
	private static final InetAddressValidator IP_VALIDATOR = InetAddressValidator.getInstance();
	
	private HostNameUtils() {}
	
	public static boolean isValidIp(String ip) {
		if (ip == null || ip.isEmpty())
			return false;
		
		return IP_VALIDATOR.isValid(ip);
	}
	
	public static boolean isValidDns(String dns) {
		if (dns == null || dns.isEmpty())
			return false;
		
		if (dns.startsWith("*.")) {
			String withoutWildcard = dns.substring(2);
			return DOMAIN_VALIDATOR.isValid(withoutWildcard);
		}
		
		return DOMAIN_VALIDATOR.isValid(dns);
	}

}
