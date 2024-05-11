using Microsoft.AspNetCore.DataProtection;
using Server.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Web;
using static IdentityModel.OidcConstants;
using static IdentityModel.OidcConstants.Algorithms;

namespace Server.Endpoints
{
    public class AuthorizeEndpoint
    {

        /// <summary>
        /// form post 类型返回值，0：client callback 1：state 2：id token
        /// </summary>
        const string FORM_POST_FORMAT = @"<html><body onload=""javascript:document.forms[0].submit()""><form method=""post"" action=""{0}""><input type=""hidden"" name=""state"" value=""{1}""/>{2}</form></body></html>";
        const string QUERY_FORMAT = @"{0}?{1}";

        const string QUERY_PARAMETER_FORMAT = @"{0}={1}";
        const string FORM_INPUT_FORMAT = @"<input type=""hidden"" name=""{0}"" value=""{1}""/>";

        public static async Task<IResult> Authorize(IDataProtectionProvider dataProtectionProvider, HttpContext httpContext, DevKeys devKeys)
        {
            // 验证
            httpContext.Request.Query.TryGetValue(AuthorizeRequest.ResponseType, out var response_type);
            // code => authorization code flow
            // id_token / token => implicit flow
            // code & (id_token / token) => hybrid flow

            // 验证scope 等一系列操作 todo:

            var _httpresult = response_type.ToString() switch
            {
                ResponseTypes.Code => CodeResult(dataProtectionProvider, httpContext),
                ResponseTypes.Token => TokenResult(httpContext, devKeys),
                ResponseTypes.IdToken => IdTokenResult(httpContext, devKeys),
                ResponseTypes.IdTokenToken => IdTokenTokenResult(httpContext, devKeys),
                _ => Results.BadRequest(TokenErrors.UnsupportedResponseType)
            };
            return _httpresult;


            //if (response_type == "code")
            //{
            //    httpContext.Request.Query.TryGetValue(AuthorizeRequest.CodeChallenge, out var code_challenge);
            //    httpContext.Request.Query.TryGetValue(AuthorizeRequest.CodeChallengeMethod, out var code_challenge_method);
            //    // code 只使用一次,黑白名单处理重复code
            //    var auth = new AuthCodeModel
            //    {
            //        ClientID = client_id,
            //        CodeChallenge = code_challenge,
            //        //RedirectUri = redirect_uri,
            //        //CodeChallengeMethod = code_challenge_method,
            //        Expriy = DateTime.Now.AddSeconds(15),
            //        Scope = scope,
            //        Nonce = nonce
            //    };

            //    var protection = dataProtectionProvider.CreateProtector("oauth");
            //    // 生成code 并返回给client
            //    var code = protection.Protect(System.Text.Json.JsonSerializer.Serialize(auth));
            //    // code 由server生成 , state 由client生成
            //    return Results.Redirect($"{redirect_uri}?code={code}&state={state}");
            //}
            //else
            //{
            //    bool isquery = response_mode == ResponseModes.Query;
            //    var parameter_format = isquery ? QUERY_PARAMETER_FORMAT : FORM_INPUT_FORMAT;
            //    //var result_format = isquery ? QUERY_FORMAT : FORM_POST_FORMAT;

            //    var idtoken_claims = new List<Claim>(8)
            //    {
            //        new Claim(JwtRegisteredClaimNames.Sub,"123123"),
            //        new Claim(JwtRegisteredClaimNames.Name,"ash"),
            //        new Claim(JwtRegisteredClaimNames.Iat,DateTime.Now.Ticks.ToString()),
            //    };

            //    // client 端没发送nonce就不需要添加
            //    if (!string.IsNullOrEmpty(nonce))
            //        idtoken_claims.Add(new Claim(JwtRegisteredClaimNames.Nonce, nonce));

            //    List<string> form_inputs = new(5)
            //    {
            //        string.Format(parameter_format,AuthorizeResponse.State,state)
            //    };

            //    // 不支持hybrid模式, code + id_token/token 都先不支持
            //    //if (response_type.Contains("code"))
            //    //    form_inputs.Add(string.Format(FORM_INPUT_FORMAT, "code", code));

            //    // 包含token就添加 token参数
            //    if (response_type_string.Split(' ').Any(a => a == ResponseTypes.Token))
            //    {
            //        var access_token = "access_tokenaccess_tokenaccess_token";
            //        form_inputs.Add(string.Format(parameter_format, AuthorizeResponse.AccessToken, access_token));
            //        form_inputs.Add(string.Format(parameter_format, AuthorizeResponse.TokenType, TokenRequestTypes.Bearer));

            //        // id_token token 模式的id_token需要 `AtHash` claim
            //        if (response_type == ResponseTypes.IdTokenToken)
            //            idtoken_claims.Add(new Claim(JwtRegisteredClaimNames.AtHash, CryptoHelper.CreateHashClaimValue(access_token, Asymmetric.RS256)));
            //    }


            //    if (response_type_string.Contains(AuthorizeResponse.IdentityToken))
            //    {
            //        var id_token = TokenEndpoint.GeneratorToken(devKeys, client_id, idtoken_claims, DateTime.Now.AddMinutes(3));
            //        form_inputs.Add(string.Format(parameter_format, AuthorizeResponse.IdentityToken, id_token));
            //    }

            //    if (isquery)
            //    {
            //        var url = string.Format(QUERY_FORMAT, redirect_uri, string.Join('&', form_inputs));
            //        return Results.Redirect(url);
            //    }
            //    else
            //    {
            //        var body = string.Format(FORM_POST_FORMAT, redirect_uri, state, form_inputs);
            //        return Results.Content(body, "text/html");
            //    }
            //}
        }

        static IResult CodeResult(IDataProtectionProvider dataProtectionProvider, HttpContext httpContext)
        {
            httpContext.Request.Query.TryGetValue(AuthorizeRequest.CodeChallenge, out var code_challenge);
            //httpContext.Request.Query.TryGetValue(AuthorizeRequest.CodeChallengeMethod, out var code_challenge_method);
            httpContext.Request.Query.TryGetValue(AuthorizeRequest.ClientId, out var client_id);
            httpContext.Request.Query.TryGetValue(AuthorizeRequest.Scope, out var scope);
            httpContext.Request.Query.TryGetValue(AuthorizeRequest.State, out var state);
            httpContext.Request.Query.TryGetValue(AuthorizeRequest.Nonce, out var nonce);
            httpContext.Request.Query.TryGetValue(AuthorizeRequest.RedirectUri, out var redirect_uri);

            // code 只使用一次,黑白名单处理重复code
            var auth = new AuthCodeModel
            {
                ClientID = client_id,
                CodeChallenge= code_challenge,
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

        /// <summary>
        /// access token 应该包括scope claim，以便访问不同api时做权限控制
        /// claims可以添加一个sub：用户ID
        /// </summary>
        /// <param name="httpContext"></param>
        /// <param name="devKeys"></param>
        /// <returns></returns>
        static IResult TokenResult(HttpContext httpContext, DevKeys devKeys)
        {
            var token = Token(httpContext, devKeys);

            var keys = new List<KeyValuePair<string, string>>
            {
                new(AuthorizeResponse.AccessToken, token),
                new(AuthorizeResponse.TokenType, TokenRequestTypes.Bearer)
            };

            return GenerateResult(httpContext, keys);
        }

        /// <summary>
        /// id token 仅包含部分用户信息，包括用户姓名，性别，头像，手机号,角色，权限点等等
        /// 不需要包括 api resource信息，请求api时不需要携带
        /// </summary>
        /// <param name="httpContext"></param>
        /// <param name="devKeys"></param>
        /// <returns></returns>
        static IResult IdTokenResult(HttpContext httpContext, DevKeys devKeys)
        {
            var id_token = IdToken(httpContext, devKeys);
            var keys = new List<KeyValuePair<string, string>>
            {
                new( AuthorizeResponse.IdentityToken, id_token)
            };
            return GenerateResult(httpContext, keys);
        }

        static IResult IdTokenTokenResult(HttpContext httpContext, DevKeys devKeys)
        {
            var token = Token(httpContext, devKeys);

            var id_token = IdToken(httpContext, devKeys,token);
            var keys = new List<KeyValuePair<string, string>>
            {
                new(AuthorizeResponse.AccessToken, token),
                new(AuthorizeResponse.TokenType, TokenRequestTypes.Bearer),
                new( AuthorizeResponse.IdentityToken, id_token)
            };
            return GenerateResult(httpContext,keys);
        }

        static string Token(HttpContext httpContext, DevKeys devKeys)
        {
            // 根据scope 获取用户信息： 类似 ApiResource TODO：
            var claims = TokenClaims(httpContext);
            return GenerateToken(httpContext,claims, devKeys);
        }

        /// <summary>
        /// 生成Id Token
        /// </summary>
        /// <param name="httpContext"></param>
        /// <param name="devKeys"></param>
        /// <returns></returns>
        static string IdToken(HttpContext httpContext, DevKeys devKeys,string? token=null)
        {
            var claims = IdTokenClaims(httpContext);
            if(token != null)
            {
                claims.Add(new Claim(JwtRegisteredClaimNames.AtHash, CryptoHelper.CreateHashClaimValue(token, Asymmetric.RS256)));
            }
            return GenerateToken(httpContext, claims, devKeys);
        }

        static List<Claim> TokenClaims(HttpContext httpContext)
        {
            httpContext.Request.Query.TryGetValue(AuthorizeRequest.ClientId, out var client_id);
            httpContext.Request.Query.TryGetValue(AuthorizeRequest.Scope, out var scope);


            // 根据scope 获取用户信息： 类似 ApiResource TODO：
            var claims = new List<Claim>
            {
                new (JwtRegisteredClaimNames.Sub,"myuserid"),
                new (StandardScopes.OpenId,"openid"),
            };
            return claims;
        }

        static List<Claim> IdTokenClaims(HttpContext httpContext)
        {
            httpContext.Request.Query.TryGetValue(AuthorizeRequest.Scope, out var scope);
            httpContext.Request.Query.TryGetValue(AuthorizeRequest.Nonce, out var nonce);

            // 根据scope 获取用户信息： 类似 IdentityResource TODO：
            var claims = new List<Claim>(5)
            {
                new(JwtRegisteredClaimNames.Iat,DateTime.Now.ToString()),
                new(JwtRegisteredClaimNames.Sub,"my sub id")
            };

            // client 端没发送nonce就不需要添加
            if (!string.IsNullOrEmpty(nonce))
                claims.Add(new Claim(JwtRegisteredClaimNames.Nonce, nonce!));

            return claims;
        }

        static string GenerateToken(HttpContext httpContext,IEnumerable<Claim> claims,DevKeys devKeys)
        {
            httpContext.Request.Query.TryGetValue(AuthorizeRequest.ClientId, out var client_id);

            var access_token_options = new JwtSecurityToken(
                issuer: "ash.oauth",
                audience: client_id,
                claims: claims,
                expires: DateTime.Now.AddMinutes(3),
                signingCredentials: devKeys.SigningCredentials
                );
            var token = devKeys.Token_handler.WriteToken(access_token_options);
            return token;
        }


        /// <summary>
        /// 根据response_mode确定parameter_format, result_format
        /// </summary>
        /// <param name="httpContext"></param>
        /// <returns></returns>
        static IResult GenerateResult(HttpContext httpContext, IEnumerable<KeyValuePair<string, string>>? inputs)
        {
            if (inputs == null)
                return Results.BadRequest();

            // 不管是query还是form_post ，不是authorization code flow就都是返回一个form html ， 根据id_token和token来判断要哪个token
            // 这个的作用是？？？
            httpContext.Request.Query.TryGetValue(AuthorizeRequest.ResponseMode, out var response_mode);

            httpContext.Request.Query.TryGetValue(AuthorizeRequest.RedirectUri, out var redirect_uri);
            httpContext.Request.Query.TryGetValue(AuthorizeRequest.State, out var state);

            if(state.Count==0)
                return Results.BadRequest();

            bool isquery = response_mode == ResponseModes.Query;
            var parameter_format = isquery ? QUERY_PARAMETER_FORMAT : FORM_INPUT_FORMAT;

            if (isquery)
            {
                var keys = new Dictionary<string, string>(inputs)
                {
                    { AuthorizeResponse.State, state! }
                };
                var result = string.Join('&', keys.Select(a => $"{a.Key}={a.Value}"));
                var url = string.Format(QUERY_FORMAT, redirect_uri, result);
                return Results.Redirect(url);
            }
            else
            {
                var parameter = inputs.SelectMany(a => string.Format(parameter_format, a.Key, a.Value));

                var body = string.Format(FORM_POST_FORMAT, redirect_uri, state, parameter);
                return Results.Content(body, "text/html");
            }
        }


    }
}
