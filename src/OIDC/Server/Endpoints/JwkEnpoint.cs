
namespace Server.Endpoints
{
    public class JwkEnpoint
    {
        public static IResult GetJwks(DevKeys devKeys)
        {
            var keys = new List<Microsoft.IdentityModel.Tokens.JsonWebKey> { devKeys.Jwk};
            return Results.Json(new 
            {
                keys
            });
        }

    }


}
