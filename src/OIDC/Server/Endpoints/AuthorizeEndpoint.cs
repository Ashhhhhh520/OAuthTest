using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http.HttpResults;
using Server.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Server.Endpoints
{
    public class AuthorizeEndpoint
    {
        public static async Task<IResult> Authorize(IDataProtectionProvider dataProtectionProvider, HttpContext httpContext, DevKeys devKeys)
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

            // 不管是query还是form_post ，不是authorization code flow就都是返回一个form html ， 根据id_token和token来判断要哪个token
            // 这个的作用是？？？
            httpContext.Request.Query.TryGetValue("response_mode", out var response_mode);

            // 验证scope 等一系列操作 todo:


            if (response_type == "code")
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
            // else if (response_type == "id_token token")
            else
            {

                var access_token = "access_tokenaccess_tokenaccess_token";

                var idtoken_claims = new List<Claim>(8)
                {
                    new Claim(JwtRegisteredClaimNames.Sub,"123123"),
                    new Claim(JwtRegisteredClaimNames.Name,"ash"),
                    new Claim(JwtRegisteredClaimNames.Iat,DateTime.Now.Ticks.ToString()),
                };

                // client 端没发送nonce就不需要添加
                if (!string.IsNullOrEmpty(nonce))
                    idtoken_claims.Add(new Claim(JwtRegisteredClaimNames.Nonce, nonce));

                // id_token token 模式需要 AtHash
                if (response_type == "id_token token")
                    idtoken_claims.Add(new Claim(JwtRegisteredClaimNames.AtHash, CryptoHelper.CreateHashClaimValue(access_token, "rs256")));

                // id token 会过期吗?
                var id_token = TokenEndpoint.GeneratorToken(devKeys, client_id, idtoken_claims, DateTime.Now.AddMinutes(3));

                var body = string.Format(FORM_POST_FORMAT, redirect_uri, state, id_token, access_token, "Bearer");
                return Results.Content(body, "text/html");
            }
        }

        /// <summary>
        /// form post 类型返回值，0：client callback 1：state 2：id token
        /// </summary>
        const string FORM_POST_FORMAT = @"<html>
   <head><title>Submit This Form</title></head>
   <body onload=""javascript:document.forms[0].submit()"">
    <form method=""post"" action=""{0}"">
      <input type=""hidden"" name=""state""
       value=""{1}""/>
      <input type=""hidden"" name=""id_token""
       value=""{2}""/>
      <input type=""hidden"" name=""access_token""
       value=""{3}""/>
<input type=""hidden"" name=""token_type""
       value=""{4}""/>
    </form>
   </body>
  </html>";
    }

}
