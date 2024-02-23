namespace Server.Middlewares
{
    public class ValidOAuthParameterMiddleware
    {
        private readonly RequestDelegate next;

        public ValidOAuthParameterMiddleware(RequestDelegate _next)
        {
            next = _next;
        }


        public async Task Invoke(HttpContext httpContext)
        {

            System.Diagnostics.Debug.WriteLine($"----------------------------- ValidOAuthParameterMiddleware:{httpContext.Request.Path.Value} --------------------------------");
            // 
            if (httpContext.Request.Path.Value?.Contains("/oauth/authorize") ??false)
            {
                // 验证几个oauth 配置
                httpContext.Request.Query.TryGetValue("response_type", out var response_type);
                httpContext.Request.Query.TryGetValue("client_id", out var client_id);
                httpContext.Request.Query.TryGetValue("code_challenge", out var code_challenge);
                httpContext.Request.Query.TryGetValue("code_challenge_method", out var code_challenge_method);
                httpContext.Request.Query.TryGetValue("redirect_uri", out var redirect_uri);
                httpContext.Request.Query.TryGetValue("scope", out var scope);
                httpContext.Request.Query.TryGetValue("state", out var state);
                httpContext.Request.Query.TryGetValue("nonce", out var nonce);

                // 验证client , response type , scope 是否跟server配置相同

            }
            else if(httpContext.Request.Path.Value?.Contains("/oauth/token") ?? false)
            {
                // 验证client 的secret 是否正确


            }

            await next(httpContext);
        }
    }
}
