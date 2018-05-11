package uk.gov.ida.eidas.trustanchor;

import javax.security.auth.x500.X500Principal;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.function.BinaryOperator;
import java.util.function.Function;
import java.util.stream.Collectors;

public class CertificateSorter {
    public static List<X509Certificate> sort(List<X509Certificate> certificates) {

        if (certificates.size() <= 1) {
            return certificates;
        }

        List<X500Principal> issuers = issuerX500s(certificates);

        return certificates.stream()
                .filter(c -> !issuers.contains(c.getSubjectX500Principal()))
                .reduce(limitToOneChild())
                .map(getSortedChain(certificates))
                .orElse(new LinkedList<>());
    }

    private static BinaryOperator<X509Certificate> limitToOneChild() {
        return (element, otherElement) -> {
            throw new IllegalArgumentException("Found multiple certificates without issuers");
        };
    }

    private static List<X500Principal> issuerX500s(List<X509Certificate> certificates) {
        return certificates.stream()
                .map(X509Certificate::getIssuerX500Principal)
                .collect(Collectors.toList());
    }


    private static Function<X509Certificate, List<X509Certificate>> getSortedChain(List<X509Certificate> x509Certificates) {
        return child -> {
            List<X509Certificate> sortedList = new LinkedList<>();
            sortedList.add(child);

            List<X509Certificate> sublist = x509Certificates.stream()
                    .filter(c -> c != child)
                    .collect(Collectors.toList());

            sortedList.addAll(findParent(child, sublist));
            return sortedList;
        };
    }

    private static List<X509Certificate> findParent(X509Certificate firstCert, List<X509Certificate> x509Certificates) {
        return x509Certificates.stream()
                .filter(cert -> Objects.equals(cert.getSubjectX500Principal(), firstCert.getIssuerX500Principal()))
                .findFirst()
                .map(getSortedChain(x509Certificates))
                .orElse(new LinkedList<>());
    }
}
