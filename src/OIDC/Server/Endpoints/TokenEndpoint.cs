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
            var body = (await httpContext.Request.BodyReader.ReadAsync()).Buffer;
            var query = HttpUtility.ParseQueryString(Encoding.UTF8.GetString(body));

            // authorzation_code 和 refresh_token 区分获取token和刷新token
            var grant_type = query.Get("grant_type");
            var clientid = query.Get("client_id");
            // 与客户端配置对比，验证客户端密钥，密钥不参与token生成 todo:
            var clientsecret = query.Get("client_secret");

            if (grant_type == "refresh_token" )
            {
                var scope = query.Get("scope");
                var access_token_claims = new List<Claim>
                {
                    new Claim("custom_claim","custom_claim_value"),
                    new Claim("scope",scope??"")
                };
                var access_token = GeneratorToken(devKeys, clientid, access_token_claims, DateTime.Now.AddMinutes(3));
                return Results.Json(new
                {
                    access_token,
                    token_type = "Bearer",
                    expires_in = DateTime.Now.AddSeconds(15),
                    refresh_token = "refresh_token test",
                });
            }
            else if(grant_type =="code")
            {
                // 验证code 以换取token
                var code = query.Get("code");
                var code_verifier = query.Get("code_verifier");
                if (!dataProtectionProvider.VerifyCode(code, code_verifier, out var auth))
                {
                    return Results.BadRequest("invalid code!");
                }

                var access_token_claims = new List<Claim>
                {
                    new Claim("custom_claim","custom_claim_value"),
                    new Claim("scope",auth.Scope)
                };
                var access_token = GeneratorToken(devKeys, clientid, access_token_claims, DateTime.Now.AddMinutes(3));
                var idtoken_claims = new List<Claim>()
                {
                    new Claim(JwtRegisteredClaimNames.Sub,"123123"),
                    new Claim(JwtRegisteredClaimNames.Name,"ash"),
                    new Claim(JwtRegisteredClaimNames.Iat,DateTime.Now.Ticks.ToString()),
                    // id token 默认需要验证nonce , Client端可以配置不验证
                    new Claim(JwtRegisteredClaimNames.Nonce,auth.Nonce)
                };
                // id token 会过期吗?
                var id_token = GeneratorToken(devKeys, clientid, idtoken_claims,DateTime.Now.AddMinutes(3));
                return Results.Json(new
                {
                    access_token = access_token,
                    token_type = "Bearer",
                    expires_in = DateTime.Now.AddSeconds(15),
                    refresh_token = "refresh_token test",
                    id_token = id_token,
                });
            }
            else
            {
                var access_token_claims = new List<Claim> { };
                var access_token = GeneratorToken(devKeys, clientid, access_token_claims, DateTime.Now.AddMinutes(3));
                return Results.Json(new
                {
                    access_token = access_token,
                    token_type = "Bearer",
                    expires_in = DateTime.Now.AddSeconds(15),
                });
            }
        }


        /// <summary>
        /// 生成 token,算法有限制,HmacSha256 能正常运行
        /// </summary>
        /// <param name="devKeys"></param>
        /// <param name="clientid"></param>
        /// <param name="claims"></param>
        /// <param name="exp"></param>
        /// <returns></returns>
        static string? GeneratorToken(DevKeys devKeys,string? clientid,List<Claim> claims,DateTime exp)
        {
            // var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(clientsecret!));
            var id_token_options = new JwtSecurityToken(
                issuer: "ash.oauth",
                audience: clientid,
                claims: claims,
                expires: exp,
                signingCredentials: devKeys.SigningCredentials
                );

            var token = devKeys.Token_handler.WriteToken(id_token_options);
            return token;
        }
    }

}
