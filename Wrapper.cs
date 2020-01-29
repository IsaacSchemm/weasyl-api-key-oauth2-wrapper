using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System.Net.Http;
using System.Net;
using System.Net.Http.Headers;
using System.Web;
using System.Text;

namespace Wrapper {
    public static class Wrapper {
        [FunctionName("auth")]
        public static IActionResult Auth([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = null)] HttpRequest req) {
            string response_type = req.Query["response_type"];
            if (response_type != "code")
                return new BadRequestObjectResult(new { error = "The response_type is invalid or missing." });

            string redirect_uri = req.Query["redirect_uri"];
            if (Uri.TryCreate(redirect_uri, UriKind.Absolute, out Uri _) == false)
                return new BadRequestObjectResult(new { error = "The redirect_uri is invalid or missing." });

            StringBuilder hidden_inputs = new StringBuilder();
            hidden_inputs.AppendLine($"<input type='hidden' name='redirect_uri' value='{HttpUtility.HtmlAttributeEncode(redirect_uri)}' />");

            string state = req.Query["state"];
            if (state != null)
                hidden_inputs.AppendLine($"<input type='hidden' name='state' value='{HttpUtility.HtmlAttributeEncode(state)}' />");

            string html = string.Format(@"<!DOCTYPE html>
<html>
    <head>
        <title>Weasyl API Key OAuth2 Wrapper</title>
    </head>
<body>
    <p>
        Enter your Weasyl API key below.<br />
        You can obtain an API key by visiting the <a href='https://www.weasyl.com/control/apikeys'>Manage API Keys</a> page on the Weasyl site.
    </p>
    <form action='postback' method='post'>
        {0}
        <input type='text' name='api_key' />
        <input type='submit' value='Submit' />
    </form>
</body>
</html>", hidden_inputs.ToString());
            return new FileContentResult(Encoding.UTF8.GetBytes(html), "text/html");
        }

        [FunctionName("postback")]
        public static IActionResult Postback([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = null)] HttpRequest req) {
            string redirect_uri = req.Form["redirect_uri"];
            var uriBuilder = new UriBuilder(redirect_uri);

            var query = HttpUtility.ParseQueryString(uriBuilder.Query);

            string api_key = req.Form["api_key"];
            if (api_key != null)
                query["code"] = api_key;

            string state = req.Form["state"];
            if (state != null)
                query["state"] = state;

            uriBuilder.Query = query.ToString();
            return new RedirectResult(uriBuilder.ToString());
        }

        [FunctionName("token")]
        public static IActionResult Token([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = null)] HttpRequest req) {
            string grant_type = req.Form["grant_type"];
            if (grant_type != "authorization_code") {
                return new BadRequestObjectResult(new { error = "The grant_type is invalid or missing." });
            }

            string code = req.Form["code"];
            if (string.IsNullOrEmpty(code)) {
                return new BadRequestObjectResult(new { error = "The code is invalid or missing." });
            }

            return new OkObjectResult(new {
                access_token = code,
                token_type = "weasyl"
            });
        }
    }
}
