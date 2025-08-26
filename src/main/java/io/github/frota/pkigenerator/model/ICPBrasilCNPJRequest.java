package io.github.frota.pkigenerator.model;

import io.github.frota.pkigenerator.util.CertificateTypeEnum;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Set;

@NoArgsConstructor
@AllArgsConstructor
@Builder
@Data
public class ICPBrasilCNPJRequest {

	private String nome;
	private String cnpj;
	private String email;
	private String nomeResponsavel;
	private String cpfResponsavel;
	private LocalDate dataNascimentoResponsavel;
	private CertificateTypeEnum certificateTypeEnum;
	
	private LocalDateTime notAfter;

}
