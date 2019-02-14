using System;
using System.Linq;
using System.Threading.Tasks;
using Certes;
using Certes.Acme;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Host;
using Microsoft.Extensions.Logging;

namespace InFurSecDen.Utils.AcmeDnsSolver
{
    public static class AcmeDnsSolver
    {
        [FunctionName("InFurSecDen.Utils.AcmeDnsSolver")]
        public static async Task Run([TimerTrigger("29 4 1 */2 *")]TimerInfo myTimer, ILogger log)
        {
            // Creating new ACME account
            var acme = new AcmeContext(WellKnownServers.LetsEncryptStagingV2);
            var account = await acme.NewAccount("tcfox@tc.nz", true);

            // Save the account key for later use
            var pemKey = acme.AccountKey.ToPem();

            // Load the saved account key
            //var accountKey = KeyFactory.FromPem(pemKey);
            //var acme = new AcmeContext(WellKnownServers.LetsEncryptStagingV2, accountKey);
            //var account = await acme.Account();

            // Place a certificate order
            var order = await acme.NewOrder(new[] { "login.furry.nz" });

            // Generate the value for DNS TXT record
            var authz = (await order.Authorizations()).First();
            var dnsChallenge = await authz.Dns();
            var dnsTxt = acme.AccountKey.DnsTxt(dnsChallenge.Token);

            // DO THE AZURE DNS THING HERE

            // Validate the DNS challenge
            await dnsChallenge.Validate();

            // Get the Certificate
            var privateKey = KeyFactory.NewKey(KeyAlgorithm.ES256);
            var cert = await order.Generate(new CsrInfo
            {
                CountryName = "NZ",
                State = "Wellington",
                Locality = "Wellington",
                Organization = "NZFurs",
                OrganizationUnit = "Dev",
                CommonName = "login.furry.nz",
            }, privateKey);

            // Export full chain certification
            var certPem = cert.ToPem();

            // Export PFX
            var pfxBuilder = cert.ToPfx(privateKey);
            var pfx = pfxBuilder.Build("my-cert", "abcd1234");

            // EXPORT CERTIFICATE TO AZURE KEY VAULT CERTIFICATES

            // CLEAN UP AZURE DNS

            // NOTIFY SERVERS TO CLEAN THEIR CONFIG (or just reboot them, whatever)
        }
    }
}
