package io.github.frota.pkigenerator.util;

import java.util.Set;

public final class CpfCnpjUtils {
	
	private static final Set<String> INVALID_CPFS = Set.of(
			"00000000000", "11111111111", "22222222222", "33333333333", "44444444444",
			"55555555555", "66666666666", "77777777777", "88888888888", "99999999999");
	
	private static final Set<String> INVALID_CNPJS = Set.of(
			"00000000000000", "11111111111111", "22222222222222", "33333333333333", "44444444444444",
			"55555555555555", "66666666666666", "77777777777777", "88888888888888", "99999999999999");
	
	private CpfCnpjUtils() {}
	
	public static boolean isCpf(String cpf) {
		if (cpf == null || cpf.length() != 11 || !cpf.matches("^\\d+$"))
			return false;
		
		if (INVALID_CPFS.contains(cpf))
			return false;
		
		char chk10 = calcCheckDigitMod11(cpf.substring(0, 9), 11);
		if (chk10 != cpf.charAt(9))
			return false;
		
		char chk11 = calcCheckDigitMod11(cpf.substring(0, 10), 11);
		if (chk11 != cpf.charAt(10))
			return false;
		
		return true;
	}
	
	public static boolean isCnpj(String cnpj, boolean allowAlpha) {
		if (cnpj == null || cnpj.length() != 14)
			return false;
		
		if (allowAlpha) {
			if (!cnpj.matches("^[0-9A-Z]+$"))
				return false;
		} else {
			if (!cnpj.matches("^\\d+$"))
				return false;
		}
		
		if (INVALID_CNPJS.contains(cnpj))
			return false;
		
		char chk13 = calcCheckDigitMod11(cnpj.substring(0, 12), 9);
		if (chk13 != cnpj.charAt(12))
			return false;
		
		char chk14 = calcCheckDigitMod11(cnpj.substring(0, 13), 9);
		if (chk14 != cnpj.charAt(13))
			return false;
		
		return true;
	}
	
	public static boolean isCnpj(String cnpj) {
		return isCnpj(cnpj, true);
	}
	
	// See http://www.cjdinfo.com.br/solucao-java-calculo-digito-modulo-11-cpf-cnpj-pis-etc
	private static char calcCheckDigitMod11(String dado, int limMult) {
		int sum = 0;
		int mult = 2;
		
		for (int i = dado.length() - 1; i >= 0; i--) {
			int dig = (dado.charAt(i) - 48);
			sum += mult * dig;
			if (++mult > limMult) mult = 2;
		}
		
		int r = 11 - (sum % 11);
		
		if (r == 10 || r == 11) {
			return '0';
		} else {
			return (char) (r + 48);
		}
	}

}
