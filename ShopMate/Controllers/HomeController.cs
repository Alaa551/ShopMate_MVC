using Microsoft.AspNetCore.Mvc;

namespace ShopMate.Controllers
{
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}
