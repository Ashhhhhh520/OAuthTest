using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Server.Models;
using System.Security.Cryptography;
using System.Text;

namespace Server.Extensions
{
    public static class VerifyExtension
    {
        /// <summary>
        /// 验证code , exprie 时间, 是否多次使用 , etc...
        /// </summary>
        /// <param name="code"></param>
        /// <param name="verifyer"></param>
        /// <param name="scope"></param>
        /// <returns></returns>
        public static bool VerifyCode(this IDataProtectionProvider dataProtectionProvider,string code, string verifyer, out AuthCodeModel authcode)
        {
            var protector = dataProtectionProvider.CreateProtector("oauth");
            var auth = System.Text.Json.JsonSerializer.Deserialize<AuthCodeModel>(protector.Unprotect(code));

            var sha256 = SHA256.HashData(Encoding.ASCII.GetBytes(verifyer));

            var verfiy = Base64UrlTextEncoder.Encode(sha256);

            authcode = auth;

            return verfiy == auth?.CodeChallenge;
        }
    }
}
