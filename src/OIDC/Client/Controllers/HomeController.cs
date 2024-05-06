using Client.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;

namespace Client.Controllers
{
    public class HomeController(ILogger<HomeController> logger) : Controller
    {
        public IActionResult Index()
        {
            
            return View();
        }

        [Authorize]
        public IActionResult Logout()
        {

            return Redirect("/");
        }

        [Authorize]
        public async Task<IActionResult> Privacy()
        {
            var id_token =await HttpContext.GetTokenAsync("id_token");
            System.Diagnostics.Debug.WriteLine($"id_token:{id_token}");
            var access_token =await HttpContext.GetTokenAsync("access_token");
            System.Diagnostics.Debug.WriteLine($"token:{access_token}");
            foreach (var item in HttpContext.User.Claims)
            {
                System.Diagnostics.Debug.WriteLine($"{item.Type} : {item.Value}");
            }
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
