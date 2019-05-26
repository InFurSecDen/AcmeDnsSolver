using System;
namespace InFurSecDen.Utils.AcmeDnsSolver.Options
{
    public class AcmeCertificateOptions
    {
        public object CommonName { get; set; }
        public string OrganizationUnit { get; set; }
        public string Organization { get; set; }
        public string Locality { get; set; }
        public string State { get; set; }
        public string CountryIso3166 { get; set; }
}
}
