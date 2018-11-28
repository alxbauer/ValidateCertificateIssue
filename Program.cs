using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ValidateCertificateIssue
{
    class Program
    {
        static X509Certificate rootCert;
        static X509Certificate intermediateCert;

        static void Main(string[] args)
        {
            rootCert = LoadCertificate(@"certs\root.crt");
            intermediateCert = LoadCertificate(@"certs\intermediate.crt");

            X509Certificate rsaSignedCert = LoadCertificate(@"certs\rsa-signed.crt");
            ValidateCertificateIssue(rsaSignedCert);

            X509Certificate rsaPssSignedCert = LoadCertificate(@"certs\rsa-pss-signed.crt");
            ValidateCertificateIssue(rsaPssSignedCert);

            Console.WriteLine("Press any key ...");
            Console.Read();
        }

        private static void ValidateCertificateIssue(X509Certificate targetCert)
        {
            Console.WriteLine("Validate: " + targetCert.SubjectDN);
            Console.WriteLine("SigAlgName: " + targetCert.SigAlgName);
            try
            {
                // Trusted anchors
                HashSet trustedAnchors = new HashSet();
                trustedAnchors.Add(new TrustAnchor(rootCert, null));

                // Certificate chain
                List<X509Certificate> certChain = new List<X509Certificate> { targetCert, intermediateCert };
                IX509Store chainStore = X509StoreFactory.Create("CERTIFICATE/COLLECTION", new X509CollectionStoreParameters(certChain));

                // Selector for the target certificate
                X509CertStoreSelector target = new X509CertStoreSelector();
                target.Certificate = targetCert;

                // Set builder parameters
                PkixBuilderParameters builderParameters = new PkixBuilderParameters(trustedAnchors, target);
                builderParameters.AddStore(chainStore);
                builderParameters.IsRevocationEnabled = false;

                PkixCertPathBuilder certPathBuilder = new PkixCertPathBuilder();
                PkixCertPathBuilderResult builderResult = certPathBuilder.Build(builderParameters);

                Console.WriteLine("Certificate successfuly validated.");
            }
            catch(Exception ex)
            {
                Console.WriteLine("Certificate validation failed: " + ex.Message);
            }

            Console.WriteLine("");
        }

        private static X509Certificate LoadCertificate(string filename)
        {
            using (FileStream fs = File.OpenRead(filename))
            {
                X509CertificateParser p = new X509CertificateParser();
                return p.ReadCertificate(fs);
            }
        }
    }
}
