
using IdentityModel;

namespace Server.Endpoints
{
    public class DiscoveryEndpoint
    {

        public static IResult GetDiscoveryDoc(HttpContext httpContext)
        {
            var doc = new Dictionary<string, object>
            {
                { OidcConstants.Discovery.Issuer, "ash.oauth" },

                { OidcConstants.Discovery.AuthorizationEndpoint, "http://localhost:5021/oauth/authorize" },
                { OidcConstants.Discovery.UserInfoEndpoint, "http://localhost:5021/oauth/userinfo" },
                { OidcConstants.Discovery.TokenEndpoint, "http://localhost:5021/oauth/token" },
                { OidcConstants.Discovery.DiscoveryEndpoint, "http://localhost:5021/.well-known/openid-configuration" },
                { OidcConstants.Discovery.JwksUri, "http://localhost:5021/oauth/jwks" },

                { OidcConstants.Discovery.ClaimsSupported, new string[]{ "sid","email","name" } },
                { OidcConstants.Discovery.ScopesSupported, new string[]{ "openid","profile","api1","api2","client1","client2" } },
                { OidcConstants.Discovery.ResponseTypesSupported, new string[]{ "code", "token" ,"id_token" } },
                { OidcConstants.Discovery.SubjectTypesSupported, new string[]{ "pairwise","public" } },
                { OidcConstants.Discovery.IdTokenSigningAlgorithmsSupported, new string[]{ "RS256" } }

            };

            return Results.Json(doc);
        }

    }
}
