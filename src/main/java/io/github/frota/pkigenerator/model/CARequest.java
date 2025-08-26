package io.github.frota.pkigenerator.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@NoArgsConstructor
@AllArgsConstructor
@Builder
@Data
public class CARequest { // for root and intermediate CA certificates creation

	@Builder.Default
	private String countryCode = "BR"; // C
	private String organization;       // O
	private String organizationalUnit; // OU
	private String commonName;         // CN
	
	private long expirationYears;
	private LocalDateTime notAfter;
	
	private String cpsPointerUri; // 2.5.29.32
	private String crlDistributionPointUri; // 2.5.29.31

}
