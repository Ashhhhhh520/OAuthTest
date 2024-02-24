using Microsoft.AspNetCore.DataProtection;
using Microsoft.IdentityModel.Tokens;
using Server.Extensions;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Web;

namespace Server.Endpoints
{
    public class TokenEndpoint
    {
        public static async Task<IResult> GetToken(IDataProtectionProvider dataProtectionProvider,HttpContext httpContext,DevKeys devKeys)
        {
            // 验证code 以换取token

            var body = (await httpContext.Request.BodyReader.ReadAsync()).Buffer;
            var query = HttpUtility.ParseQueryString(Encoding.UTF8.GetString(body));
            var code = query.Get("code");
            var code_verifier = query.Get("code_verifier");
            var clientid = query.Get("client_id");
            // 客户端密钥 ， 跟token有关系吗？
            var clientsecret = query.Get("client_secret");

            if (!dataProtectionProvider.VerifyCode(code, code_verifier, out var auth))
            {
                return Results.BadRequest("invalid code!");
            }

            var access_token_claims = new List<Claim>
            {
                new Claim("custom_claim","custom_claim_value"),
                new Claim("scope",auth.Scope)
            };
            var token_handler = new JwtSecurityTokenHandler();

            // 生成 token
            //var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(clientsecret!));
            // 算法有限制,HmacSha256 能正常运行
            var creds = new SigningCredentials(devKeys.RsaSecurityKey, SecurityAlgorithms.RsaSha256);

            var access_token_options = new JwtSecurityToken(
                issuer: "ash.oauth",
                audience: clientid,
                claims: access_token_claims,
                expires: DateTime.Now.AddMinutes(15),
                signingCredentials: creds
                );
            var access_token = token_handler.WriteToken(access_token_options);

            var idtoken_claims = new List<Claim>()
            {
                new Claim(JwtRegisteredClaimNames.Sub,"123123"),
                new Claim(JwtRegisteredClaimNames.Name,"ash"),
                new Claim(JwtRegisteredClaimNames.Iat,DateTime.Now.Ticks.ToString()),
                // id token 默认需要验证nonce , Client端可以配置不验证
                new Claim(JwtRegisteredClaimNames.Nonce,auth.Nonce)
            };
            var id_token_options = new JwtSecurityToken(
                issuer: "ash.oauth",
                audience: clientid,
                claims: idtoken_claims,
                expires: DateTime.Now.AddMinutes(15),
                signingCredentials: creds
                );

            var id_token = token_handler.WriteToken(id_token_options);
            return Results.Json(new
            {
                access_token = access_token,
                token_type = "Bearer",
                expires_in = DateTime.Now.AddSeconds(15),
                refresh_token = "refresh_token test",
                id_token=id_token,
            });
        }
    }
}
