using Client.Models;
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
        public IActionResult Privacy()
        {
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
