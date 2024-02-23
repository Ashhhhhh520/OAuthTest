using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System.Web;

namespace Server.Controllers
{
    public class OAuthController : Controller
    {
        private readonly IDataProtectionProvider dataProtectionProvider;

        public OAuthController(IDataProtectionProvider dataProtectionProvider)
        {
            this.dataProtectionProvider = dataProtectionProvider;
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
    }
}
