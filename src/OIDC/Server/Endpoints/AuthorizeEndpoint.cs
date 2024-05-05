using Microsoft.AspNetCore.DataProtection;
using Server.Models;
using System.Text;

namespace Server.Endpoints
{
    public class AuthorizeEndpoint
    {
        public static async Task<IResult> Authorize(IDataProtectionProvider dataProtectionProvider,HttpContext httpContext)
        {
            // 验证
            httpContext.Request.Query.TryGetValue("response_type", out var response_type);

            // code => authorization code flow
            // id_token / token => implicit flow
            // code & (id_token / token) => hybrid flow

            httpContext.Request.Query.TryGetValue("client_id", out var client_id);
            httpContext.Request.Query.TryGetValue("redirect_uri", out var redirect_uri);
            httpContext.Request.Query.TryGetValue("scope", out var scope);
            httpContext.Request.Query.TryGetValue("state", out var state);
            httpContext.Request.Query.TryGetValue("nonce", out var nonce);

            // 验证scope 等一系列操作 todo:


            if (response_type.Contains("code"))
            {
                httpContext.Request.Query.TryGetValue("code_challenge", out var code_challenge);
                httpContext.Request.Query.TryGetValue("code_challenge_method", out var code_challenge_method);
                // code 只使用一次,黑白名单处理重复code
                var auth = new AuthCodeModel
                {
                    ClientID = client_id,
                    CodeChallenge = code_challenge,
                    //RedirectUri = redirect_uri,
                    //CodeChallengeMethod = code_challenge_method,
                    Expriy = DateTime.Now.AddSeconds(15),
                    Scope = scope,
                    Nonce = nonce
                };

                var protection = dataProtectionProvider.CreateProtector("oauth");
                // 生成code 并返回给client
                var code = protection.Protect(System.Text.Json.JsonSerializer.Serialize(auth));
                // code 由server生成 , state 由client生成
                return Results.Redirect($"{redirect_uri}?code={code}&state={state}");
            }
            else
            {
                httpContext.Response.ContentType = "application/x-www-form-urlencoded";

                var uri =new StringBuilder($"{redirect_uri}?state={state}");
                if (response_type.Contains("id_token"))
                    uri.Append($"&id_token=test_idtokentest_idtokentest_idtokentest_idtoken");
                if (response_type.Contains("token"))
                    uri.Append($"&token=test_tokentest_tokentest_tokentest_tokentest_token");
                return Results.Redirect(uri.ToString());
            }

        }


        //public static async Task<IResult> SubmitAuthorize(IDataProtectionProvider dataProtectionProvider, HttpContext httpContext)
        //{
        //    // 验证code 以换取token

        //    var body = (await httpContext.Request.BodyReader.ReadAsync()).Buffer;
        //    var query = HttpUtility.ParseQueryString(Encoding.UTF8.GetString(body));
        //    var code = query.Get("code");
        //    var code_verifier = query.Get("code_verifier");
        //    var clientid = query.Get("client_id");
        //    // 密钥
        //    var clientsecret = query.Get("client_secret");

        //    if (!dataProtectionProvider.VerifyCode(code, code_verifier, out var scope))
        //    {
        //        return Results.BadRequest("invalid code!");
        //    }

        //    var claims = new List<Claim>
        //    {
        //        new Claim(JwtRegisteredClaimNames.Name,"ash"),
        //        new Claim(JwtRegisteredClaimNames.Sid,"123123"),
        //        new Claim("custom_claim","custom_claim_value"),
        //        new Claim("scope",scope)
        //    };
        //    // 生成 token
        //    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(clientsecret!));
        //    var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        //    var tokenOptions = new JwtSecurityToken(
        //        issuer: "avd.oauth",
        //        audience: clientid,
        //        claims: claims,
        //        expires: DateTime.Now.AddSeconds(15),
        //        signingCredentials: creds
        //        );
        //    var token = new JwtSecurityTokenHandler().WriteToken(tokenOptions);
        //    return Results.Json(new
        //    {
        //        access_token = token,
        //        token_type = "Bearer",
        //        expires_in = DateTime.Now.AddSeconds(15),
        //        refresh_token = "refresh_token test"
        //    });
        //}

    }

}
