package io.github.frota.pkigenerator.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.Set;

@NoArgsConstructor
@AllArgsConstructor
@Builder
@Data
public class WebsiteRequest {

	private String commonName;
	private Set<String> dnsNames;
	private Set<String> ipAddresses;
	
	private LocalDateTime notAfter;

}
