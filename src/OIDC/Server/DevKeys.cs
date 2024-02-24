using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;

namespace Server
{
    public class DevKeys
    {
        public RSA RsaKey { get; }

        public RsaSecurityKey RsaSecurityKey =>new RsaSecurityKey(RsaKey);
        public JsonWebKey Jwk;
        public DevKeys(IWebHostEnvironment webHostEnvironment)
        {
            RsaKey = RSA.Create();
            var path = Path.Combine(webHostEnvironment.ContentRootPath, "crypto_key");
            if(!File.Exists(path))
            {
                throw new Exception("no crypto_key file");
            }
            RsaKey.ImportRSAPrivateKey(File.ReadAllBytes(path), out _);
            Jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(RsaSecurityKey);
            Jwk.Kid = Guid.NewGuid().ToString();
        }


    }
}
