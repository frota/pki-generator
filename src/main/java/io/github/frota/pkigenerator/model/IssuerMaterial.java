package io.github.frota.pkigenerator.model;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

public record IssuerMaterial(X509Certificate issuerCertificate, KeyPair issuerKeyPair, X509Certificate[] issuerChain) {}
