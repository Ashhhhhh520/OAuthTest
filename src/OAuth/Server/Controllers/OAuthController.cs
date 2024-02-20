using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Buffers.Text;
using System.IdentityModel.Tokens.Jwt;
using System.Runtime.Intrinsics.Arm;
using System.Security;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using JwtRegisteredClaimNames = Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames;

namespace Server.Controllers
{
    public class OAuthController : Controller
    {
        private readonly IDataProtectionProvider dataProtectionProvider;
        private readonly DevKeys devKeys;

        public OAuthController(IDataProtectionProvider dataProtectionProvider,DevKeys devKeys)
        {
            this.dataProtectionProvider = dataProtectionProvider;
            this.devKeys = devKeys;
        }

        [HttpGet("/login")]
        public IActionResult Login()
        {
            // verify client config  TODO:



            var query = HttpContext.Request.Query;
            ViewBag.Url =$"/login?returnUrl={HttpUtility.UrlEncode(query["returnUrl"])}";
            return View();
        }


        [HttpPost("/login")]
        public async Task<IActionResult> SubmitLogin()
        {
            // login todo:



            var query = HttpContext.Request.Query;
            var principal = new ClaimsPrincipal(new ClaimsIdentity(
                    new Claim[]
                    {
                        new Claim(ClaimTypes.Name,"ash")
                    },
                    "cookie"
                ));

            await HttpContext.SignInAsync("cookie", principal);
            return Redirect(query["returnUrl"]!);
        }


        [HttpGet("/oauth/authorize")]
        [Authorize]
        public IActionResult Authorize()
        {
            // 验证
            HttpContext.Request.Query.TryGetValue("response_type", out var response_type);
            HttpContext.Request.Query.TryGetValue("client_id", out var client_id);
            HttpContext.Request.Query.TryGetValue("code_challenge", out var code_challenge);
            HttpContext.Request.Query.TryGetValue("code_challenge_method", out var code_challenge_method);
            HttpContext.Request.Query.TryGetValue("redirect_uri", out var redirect_uri);
            HttpContext.Request.Query.TryGetValue("scope", out var scope);
            HttpContext.Request.Query.TryGetValue("state", out var state);

            // 验证scope 等一系列操作

            // code 只使用一次,黑白名单处理重复code
            var auth = new AuthCode { 
                ClientID=client_id,
                CodeChallenge=code_challenge,
                CodeChallengeMethod=code_challenge_method,
                Expriy=DateTime.Now.AddSeconds(15),
                RedirectUri=redirect_uri,
                Scope=scope
            };

            var protection = dataProtectionProvider.CreateProtector("oauth");
            // 生成code 并返回给client
            var code = protection.Protect(System.Text.Json.JsonSerializer.Serialize(auth));

            // code 由server生成 , state 由client生成
            return Redirect($"{redirect_uri}?code={code}&state={state}&iss={HttpUtility.UrlEncode("https://localhost:7259")}");
        }


        [HttpPost("/oauth/token")]
        public async Task<IActionResult> Token()
        {
            // 验证code 以换取token

            var body = (await HttpContext.Request.BodyReader.ReadAsync()).Buffer;
            var query = HttpUtility.ParseQueryString(Encoding.UTF8.GetString(body));
            var code= query.Get("code");
            var code_verifier = query.Get("code_verifier");
            var clientid = query.Get("client_id");

            if (!VerifyCode(code, code_verifier,out var scope))
            {
                return BadRequest("invalid code!");
            }

            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Name,"ash"),
                new Claim(JwtRegisteredClaimNames.Sid,"123123"),
                new Claim("custom_claim","custom_claim_value"),
                new Claim("scope",scope)
            };
            // 生成 token
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("secret_key_secret_key_secret_key_secret_key"));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var tokenOptions = new JwtSecurityToken(
                issuer: "avd.oauth",
                audience: clientid,
                claims: claims,
                expires: DateTime.Now.AddMinutes(15),
                signingCredentials: creds
                );
            var token = new JwtSecurityTokenHandler().WriteToken(tokenOptions);

            //var handler = new JsonWebTokenHandler();

            //var token = handler.CreateToken(new SecurityTokenDescriptor
            //{
            //    Claims = new Dictionary<string, object>
            //    {
            //        [JwtRegisteredClaimNames.Name] = "ash",
            //        [JwtRegisteredClaimNames.UniqueName] = "6666",
            //        ["custom_claim"] = "custom claim value"
            //    },
            //    Expires = DateTime.Now.AddMinutes(15),
            //    TokenType = "Bearer",
            //    SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes("secretkeysecretkeysecretkeysecretkeysecretkeysecretkey")), SecurityAlgorithms.RsaSha256)
            //});

            return Ok(new
            {
                access_token = token,
                token_type="Bearer"
            }) ;
        }

        public bool VerifyCode(string code,string verifyer,out string scope)
        {
            var protector = dataProtectionProvider.CreateProtector("oauth");
            var auth = System.Text.Json.JsonSerializer.Deserialize<AuthCode>(protector.Unprotect(code));

            var sha256 = SHA256.HashData(Encoding.ASCII.GetBytes(verifyer));

            var verfiy = Base64UrlTextEncoder.Encode(sha256);

            scope = auth!.Scope;

            return verfiy == auth?.CodeChallenge;
        }
    }


    public class AuthCode
    {
        public required string? ClientID { get; set; }

        public required string? CodeChallenge { get; set; }

        public required string? CodeChallengeMethod { get; set; }

        public required string? RedirectUri { get; set;}

        public required DateTime Expriy { get; set; }

        public required string Scope { get; set; }
    }
}
