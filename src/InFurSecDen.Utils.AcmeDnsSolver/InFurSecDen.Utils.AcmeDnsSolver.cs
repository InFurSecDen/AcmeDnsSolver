using System;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Host;
using Microsoft.Extensions.Logging;

namespace InFurSecDen.Utils.AcmeDnsSolver
{
    public static class InFurSecDen.Utils
    {
        [FunctionName("InFurSecDen.Utils")]
    public static void Run([TimerTrigger("29 4 1 */2 *")]TimerInfo myTimer, ILogger log)
    {
        log.LogInformation($"C# Timer trigger function executed at: {DateTime.Now}");
    }
}
}
