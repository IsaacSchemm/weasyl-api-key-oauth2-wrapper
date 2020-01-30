using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Newtonsoft.Json;
using System.Net;
using System.Web;
using System.Text;

namespace Wrapper {
    public static class Wrapper {
        private static string GetClientSecret(string clientId) {
            if (clientId == null)
                return null;
            else if (!int.TryParse(clientId, out int i))
                return null;
            else
                return Environment.GetEnvironmentVariable($"ClientSecret_{i}", EnvironmentVariableTarget.Process);
        }

        private static string Encrypt(string clientSecret, string val) {
            byte[] key = Convert.FromBase64String(clientSecret);

            string enc = AESGCM.SimpleEncrypt(val, key);
            return Uri.EscapeDataString(enc);
        }

        private static string Decrypt(string clientSecret, string enc) {
            byte[] key = Convert.FromBase64String(clientSecret);

            string dec = AESGCM.SimpleDecrypt(enc, key);
            return dec;
        }

        [FunctionName("auth")]
        public static IActionResult Auth([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = null)] HttpRequest req) {
            string response_type = req.Query["response_type"];
            if (response_type != "code")
                return new BadRequestObjectResult(new { error = "The response_type is invalid or missing." });

            string client_id = req.Query["client_id"];
            string client_secret = GetClientSecret(client_id);
            if (client_secret == null)
                return new BadRequestObjectResult(new { error = "The client_id is invalid or missing." });

            string redirect_uri = req.Query["redirect_uri"];
            if (Uri.TryCreate(redirect_uri, UriKind.Absolute, out Uri _) == false)
                return new BadRequestObjectResult(new { error = "The redirect_uri is invalid or missing." });

            StringBuilder hidden_inputs = new StringBuilder();
            hidden_inputs.AppendLine($"<input type='hidden' name='client_id' value='{HttpUtility.HtmlAttributeEncode(client_id)}' />");
            hidden_inputs.AppendLine($"<input type='hidden' name='redirect_uri' value='{HttpUtility.HtmlAttributeEncode(redirect_uri)}' />");

            string state = req.Query["state"];
            if (state != null)
                hidden_inputs.AppendLine($"<input type='hidden' name='state' value='{HttpUtility.HtmlAttributeEncode(state)}' />");

            string html = string.Format(@"<!DOCTYPE html>
<html>
    <head>
        <title>Weasyl API Key OAuth2 Wrapper</title>
        <meta name='viewport' content='width=device-width, initial-scale=1'>
        <link rel='stylesheet' href='https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css' integrity='sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T' crossorigin='anonymous'>
    </head>
<body class='m-2'>
    <p>
        Enter your Weasyl API key below.<br />
        You can obtain an API key by visiting the <a href='https://www.weasyl.com/control/apikeys' target='_blank'>Manage API Keys</a> page on the Weasyl site.
    </p>
    <form action='postback' method='post' class='form-inline'>
        {0}
        <div class='form-group mr-2'>
            <input type='text' name='api_key' class='form-control' />
        </div>
        <input type='submit' value='Submit' class='btn btn-primary' />
    </form>
    <hr />
    <p class='font-weight-bold'>This page was designed for Artwork Inbox and is not part of Weasyl. By entering your API key, you are giving another app access to your account.</p>
    <hr />
    <p class='small'>
        <a href='https://github.com/IsaacSchemm/weasyl-api-key-oauth2-wrapper' target='_blank'>
            View source on GitHub
        </a>
    </p>
</body>
</html>", hidden_inputs.ToString());
            return new FileContentResult(Encoding.UTF8.GetBytes(html), "text/html");
        }

        [FunctionName("postback")]
        public static IActionResult Postback([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = null)] HttpRequest req) {
            string client_id = req.Form["client_id"];
            string client_secret = GetClientSecret(client_id);
            if (client_secret == null)
                return new BadRequestResult();

            string redirect_uri = req.Form["redirect_uri"];
            var uriBuilder = new UriBuilder(redirect_uri);

            var query = HttpUtility.ParseQueryString(uriBuilder.Query);

            string api_key = req.Form["api_key"];
            if (api_key == null)
                return new BadRequestResult();

            query["code"] = Encrypt(client_secret, api_key);

            string state = req.Form["state"];
            if (state != null)
                query["state"] = state;

            uriBuilder.Query = query.ToString();
            return new RedirectResult(uriBuilder.ToString());
        }

        [FunctionName("token")]
        public static async Task<IActionResult> Token([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = null)] HttpRequest req) {
            string client_id = req.Form["client_id"];
            string client_secret = GetClientSecret(client_id);
            if (client_secret == null)
                return new OkObjectResult(new {
                    error = "unauthorized_client"
                });

            string grant_type = req.Form["grant_type"];
            if (grant_type != "authorization_code") {
                return new OkObjectResult(new {
                    error = "unsupported_grant_type"
                });
            }

            string code = req.Form["code"];
            if (string.IsNullOrEmpty(code)) {
                return new OkObjectResult(new {
                    error = "invalid_request"
                });
            }

            string apiKey = Decrypt(client_secret, code);

            var hreq = WebRequest.CreateHttp("https://www.weasyl.com/api/whoami");
            hreq.UserAgent = "weasyl-api-key-oauth2-wrapper/0.0";
            hreq.Headers["X-Weasyl-API-Key"] = apiKey;
            try {
                using (var resp = await hreq.GetResponseAsync())
                using (var sr = new StreamReader(resp.GetResponseStream())) {
                    string json = await sr.ReadToEndAsync();
                    var user = JsonConvert.DeserializeAnonymousType(json, new { login = "", userid = 0L });

                    return new OkObjectResult(new {
                        access_token = apiKey,
                        token_type = "weasyl",
                        user.userid,
                        user.login
                    });
                }
            } catch (WebException ex) when ((ex.Response as HttpWebResponse)?.StatusCode == HttpStatusCode.Unauthorized) {
                return new OkObjectResult(new {
                    error = "invalid_grant"
                });
            } catch (WebException) {
                return new StatusCodeResult((int)HttpStatusCode.BadGateway);
            }
        }
    }
}
