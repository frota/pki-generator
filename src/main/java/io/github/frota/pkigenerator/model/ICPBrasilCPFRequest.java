package io.github.frota.pkigenerator.model;

import java.time.LocalDate;
import java.time.LocalDateTime;

import io.github.frota.pkigenerator.util.CertificateTypeEnum;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@AllArgsConstructor
@Builder
@Data
public class ICPBrasilCPFRequest {

	private String nome;
	private String cpf;
	private String email;
	private LocalDate dataNascimento;
	private CertificateTypeEnum certificateTypeEnum;
	
	private LocalDateTime notAfter;

}
