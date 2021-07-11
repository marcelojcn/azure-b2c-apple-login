using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;

namespace AppleLoginFunction
{
    public static class SignAppleLogin
    {
        [Function("SignAppleLogin")]
        public static async Task<HttpResponseData> Run([HttpTrigger(AuthorizationLevel.Anonymous, "post")] HttpRequestData req, ILogger log)
        {
            string audience = "https://appleid.apple.com";

            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            dynamic data = JsonConvert.DeserializeObject(requestBody);

            string issuer = data?.appleTeamId;
            string subject = data?.appleServiceId;
            string key = data?.appleKeyId;
            string p8key = data?.p8key;

            IList<Claim> claims = new List<Claim> {
                new Claim ("sub", subject)
            };

            CngKey cngKey = CngKey.Import(Convert.FromBase64String(p8key), CngKeyBlobFormat.Pkcs8PrivateBlob);

            SigningCredentials signingCred = new SigningCredentials(
                new ECDsaSecurityKey(new ECDsaCng(cngKey)),
                SecurityAlgorithms.EcdsaSha256
            );


            var header = new JwtHeader(signingCred);
            var payload = new JwtPayload(issuer, audience, claims, DateTime.Now, DateTime.Now.AddDays(180), DateTime.Now);

            JwtSecurityToken token = new JwtSecurityToken(header, payload);

            token.Header.TryAdd("kid", key);

            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();

            string jwt = tokenHandler.WriteToken(token);

            var response = req.CreateResponse(HttpStatusCode.OK);
            await response.WriteStringAsync(jwt).ConfigureAwait(false);
            return response;
        }
    }
}
