using System;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Azure.WebJobs.Host;

namespace SharedAccessTokenApp
{
    /// <summary>
    /// Azure Function that will generate an Event Hubs Shared Access Signature (SAS) Token. This can also be used for the Service Bus.
    /// </summary>
    public static class SASTokenFunction
    {
        [FunctionName("SASToken")]
        public static HttpResponseMessage Run([HttpTrigger(AuthorizationLevel.Anonymous, "get", "post")]HttpRequestMessage req, TraceWriter log)
        {
            log.Info("SAS Token trigger function processed a request.");

            // Parse query parameter
            var keyName = req.GetQueryNameValuePairs()
                .FirstOrDefault(q => string.Compare(q.Key, "keyName", true) == 0)
                .Value;

            // Parse query parameter
            var key = req.GetQueryNameValuePairs()
                .FirstOrDefault(q => string.Compare(q.Key, "key", true) == 0)
                .Value;

            // Parse query parameter
            var url = req.GetQueryNameValuePairs()
                .FirstOrDefault(q => string.Compare(q.Key, "uri", true) == 0)
                .Value;

            var token = CreateToken(url, keyName, key);

            // Fetching the name from the path parameter in the request URL
            return req.CreateResponse(HttpStatusCode.OK,  token);
        }

        private static string CreateToken(string resourceUri, string keyName, string key)
        {
            if (key == null) return "key parameter cannot be null";
            if (keyName == null) return "keyName parameter cannot be null";
            if (resourceUri == null) return "uri parameter cannot be null";

            var sinceEpoch = DateTime.UtcNow - new DateTime(1970, 1, 1);
            const int week = 60 * 60 * 24 * 7;
            var expiry = Convert.ToString((int)sinceEpoch.TotalSeconds + week);
            var stringToSign = WebUtility.UrlEncode(resourceUri) + "\n" + expiry;
            var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(key));
            var signature = Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(stringToSign)));
            var sasToken = String.Format(CultureInfo.InvariantCulture, "SharedAccessSignature sr={0}&sig={1}&se={2}&skn={3}", WebUtility.UrlEncode(resourceUri), WebUtility.UrlEncode(signature), expiry, keyName);
            return sasToken;
        }
    }


}
