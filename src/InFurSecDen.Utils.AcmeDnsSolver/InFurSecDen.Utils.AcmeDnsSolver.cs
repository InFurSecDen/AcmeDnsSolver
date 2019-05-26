using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Certes;
using Certes.Acme;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.Azure.Management.Dns;
using Microsoft.Azure.Management.Dns.Models;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Rest;

namespace InFurSecDen.Utils.AcmeDnsSolver
{
    public static class AcmeDnsSolver
    {
        private const string ACME_DNS_CHALLENGE_SUBDOMAIN = "_acme-challenge";

        [FunctionName("AcmeDnsSolver")]
        public static async Task Run(
            [TimerTrigger("29 4 1 */2 *"
#if DEBUG
            , RunOnStartup=true
#endif
            )] TimerInfo myTimer,
            ILogger log,
            ExecutionContext context
        )
        {
            // TODO: Get CancellationToken

            // Build Configuration from App Settings
            var config = new ConfigurationBuilder()
                .SetBasePath(context.FunctionAppDirectory)
                .AddEnvironmentVariables()
                .Build();

            // Get the Azure Authorisation Context
            var azureServiceTokenProvider = new AzureServiceTokenProvider(config["Azure:ServiceTokenProviderConnectionString"]); // https://docs.microsoft.com/en-us/azure/key-vault/service-to-service-authentication#connection-string-support

            // Get the Key Vault Client
            var keyVaultClient = new KeyVaultClient(
                new KeyVaultClient.AuthenticationCallback(azureServiceTokenProvider.KeyVaultTokenCallback)
            );

            // Get the DNS Client - https://stackoverflow.com/questions/53192345
            var azureManagementAccessToken = await azureServiceTokenProvider.GetAccessTokenAsync("https://management.azure.com");
            var azureManagementAccessTokenCredentals = new TokenCredentials(azureManagementAccessToken);
            var dnsClient = new DnsManagementClient(azureManagementAccessTokenCredentals)
            {
                SubscriptionId = config["Azure:Dns:SubscriptionId"],
            };

            // TODO: Check if the account already exists for this email address/ACME Server
            string pemKey = null;
            var keyVaultLocation = $"https://{config["Azure:KeyVault:VaultName"]}.vault.azure.net/";
            var keyVaultAcmeAccountSecretName = $"Acme--AccountKey--{config["Acme:Account:EmailAddress"]}";
            try
            {
                var secretVersions = await keyVaultClient.GetSecretVersionsAsync(keyVaultLocation, keyVaultAcmeAccountSecretName);
                if (secretVersions.Any())
                {
                    var pemKeyBundle = await keyVaultClient.GetSecretAsync(keyVaultLocation, keyVaultAcmeAccountSecretName);
                    pemKey = pemKeyBundle?.Value;
                }
            }
            catch (Exception ex)
            {
                log.LogError(ex, "Exception thrown when retrieving ACME account key");
                throw;
            }

            IAcmeContext acme;

            if (pemKey == null)
            {
                // Creating new ACME account
                acme = new AcmeContext(WellKnownServers.LetsEncryptStagingV2);
                var account = await acme.NewAccount(config["Acme:Account:EmailAddress"], true);

                // TODO: Save the account key for later use
                await keyVaultClient.SetSecretAsync(keyVaultLocation, keyVaultAcmeAccountSecretName, acme.AccountKey.ToPem(), contentType: "application/x-pem-file");
                pemKey = acme.AccountKey.ToPem();
            }
            else
            {
                // Load the saved account key
                var accountKey = KeyFactory.FromPem(pemKey);
                acme = new AcmeContext(WellKnownServers.LetsEncryptStagingV2, accountKey);
                var account = await acme.Account();
            }

            // Place a certificate order
            var order = await acme.NewOrder(new[] { config["Acme:Certificate:CommonName"] });

            // Generate the value for DNS TXT record
            var authz = (await order.Authorizations()).First();
            var dnsChallenge = await authz.Dns();
            var dnsTxt = acme.AccountKey.DnsTxt(dnsChallenge.Token);

            // Add TXT record to Azure DNS - https://docs.microsoft.com/en-us/azure/dns/dns-sdk
            var recordSetParams = new RecordSet
            {
                TTL = 60,
                TxtRecords = new List<TxtRecord>
                {
                    new TxtRecord(new List<string>{dnsTxt}),
                },
            };
            var recordSet = await dnsClient.RecordSets.CreateOrUpdateAsync(config["Azure:Dns:ResourceGroupName"], config["Azure:Dns:ZoneResourceName"], ACME_DNS_CHALLENGE_SUBDOMAIN, RecordType.TXT, recordSetParams);

            // TODO: Check/Set CAA record

            // Validate the DNS challenge
            var result = await dnsChallenge.Validate(); // TODO: Retry if not ready yet (with timeout)

            while (result.Status != Certes.Acme.Resource.ChallengeStatus.Valid)
            {
                switch (result.Status)
                {
                    case Certes.Acme.Resource.ChallengeStatus.Pending:
                    case Certes.Acme.Resource.ChallengeStatus.Processing:
                        await Task.Delay(1000);
                        break;
                    case Certes.Acme.Resource.ChallengeStatus.Invalid:
                        LogAcmeErrors(log, result.Error);
                        throw new AcmeException($"ACME challenge failed to validate:\n{result.Error.Detail}"); // TODO: Throw AggregateException
                    case Certes.Acme.Resource.ChallengeStatus.Valid:
                        continue;
                }

                result = await dnsChallenge.Validate();
            }

            // Get the Certificate
            var privateKey = KeyFactory.NewKey(KeyAlgorithm.RS256);
            var cert = await order.Generate(new CsrInfo
            {
                CountryName = config["Acme:Certificate:CountryIso3166"],
                State = config["Acme:Certificate:State"],
                Locality = config["Acme:Certificate:Locality"],
                Organization = config["Acme:Certificate:Organization"],
                OrganizationUnit = config["Acme:Certificate:OrganizationUnit"],
                CommonName = config["Acme:Certificate:CommonName"]
            }, privateKey);

            // Export full chain certification
            var certAndKeyPem = cert.ToPem() + privateKey.ToPem();

            // Export PFX
            var pfxBuilder = cert.ToPfx(privateKey);
            var pfxBytes = pfxBuilder.Build(config["Acme:Certificate:CommonName"], "");
            var pfxX509 = new X509Certificate2(pfxBytes, "", X509KeyStorageFlags.Exportable); // Exportable else doesn't work on macOS
            var pfxX509Collection = new X509Certificate2Collection(pfxX509);
            var certPolicy = new CertificatePolicy();

            // Export certificate to Key Vault
            try
            {
                await keyVaultClient.ImportCertificateAsync(keyVaultLocation, GetDashedReversedDnsName(config["Acme:Certificate:CommonName"]), pfxX509Collection, null);
            }
            catch (Exception ex)
            {
                log.LogError(ex, "An error has occured while importing the certificate and key to Key Vault");
                throw;
            }

            // Remove now useless DNS record(s) from Key Vault
            await dnsClient.RecordSets.DeleteAsync(config["Azure:Dns:ResourceGroupName"], config["Azure:Dns:ZoneResourceName"], ACME_DNS_CHALLENGE_SUBDOMAIN, RecordType.TXT);
        }

        private static string GetBase16HashString(string text)
        {
            if (text == null) throw new ArgumentNullException(nameof(text));

            var sha256 = SHA256.Create();
            var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(text));
            return BitConverter.ToString(hash).Replace("-", string.Empty);
        }

        private static string GetDashedReversedDnsName(string hostname)
        {
            return String.Join("-", hostname.Split('.').Reverse()).ToLowerInvariant();
        }

        private static void LogAcmeErrors(ILogger log, AcmeError acmeError)
        {
            log.LogError($"ACME challenge failed to validate:\n{acmeError.Detail} ({acmeError.Type})");
            foreach (var suberror in acmeError.Subproblems) LogAcmeErrors(log, suberror);
        }
    }
}
