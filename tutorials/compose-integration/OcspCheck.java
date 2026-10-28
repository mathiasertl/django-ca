/**
 * Test OCSP using a Java client.
 *
 * See: https://github.com/mathiasertl/django-ca/issues/270
 */
import java.io.*;
import java.security.cert.*;
import java.util.*;

public class OcspCheck {
  public static void main(String[] a) throws Exception {
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    X509Certificate ca, leaf;
    try (var in = new FileInputStream(a[0])) { ca = (X509Certificate) cf.generateCertificate(in); }
    try (var in = new FileInputStream(a[1])) { leaf = (X509Certificate) cf.generateCertificate(in); }

    CertPathValidator v = CertPathValidator.getInstance("PKIX");
    PKIXRevocationChecker rc = (PKIXRevocationChecker) v.getRevocationChecker();
    rc.setOptions(EnumSet.of(PKIXRevocationChecker.Option.ONLY_END_ENTITY,
                             PKIXRevocationChecker.Option.NO_FALLBACK));

    PKIXParameters p = new PKIXParameters(Set.of(new TrustAnchor(ca, null)));
    p.setRevocationEnabled(false);
    p.addCertPathChecker(rc);

    v.validate(cf.generateCertPath(List.of(leaf)), p);
    System.out.println("OK: OCSP status good");
  }
}