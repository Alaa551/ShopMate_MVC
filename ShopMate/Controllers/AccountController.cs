using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using ShopMate.ViewModels;
using System.Security.Claims;

namespace PL.Controllers
{
    public class AccountController : Controller
    {
        private readonly HttpClient _httpClient;

        public AccountController(HttpClient httpClient)
        {
            _httpClient = httpClient;
            _httpClient.BaseAddress = new Uri("https://localhost:7012");

        }




        #region login - logout

        [HttpGet]
        public IActionResult Login()
        {

            return View("login");

        }

        [HttpPost]
        public async Task<IActionResult> Login(LoginVM loginVM)
        {
            if (!ModelState.IsValid)
            {
                return View(loginVM);
            }

            var response = await _httpClient.PostAsJsonAsync($"/api/Account/Login", loginVM);
            var errors = await ApiErrorHandler.HandleApiErrorAsync(response);
            if (errors.Count == 0)
            {
                var token = await response.Content.ReadAsStringAsync();
                HttpContext.Session.SetString("JWToken", token);
                await SignInUserAsync(loginVM.Email, token);
                return RedirectToAction("Index", "Home");
            }
            foreach (var error in errors)
            {
                ModelState.AddModelError("", error);
            }
            return View(loginVM);
        }

        private async Task SignInUserAsync(string email, string token)
        {
            var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, email),
                    new Claim("Token", token)
                };

            var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            var principal = new ClaimsPrincipal(identity);

            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);
        }


        [HttpGet]
        public async Task<IActionResult> LogoutAsync()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            HttpContext.Session.Remove("JWToken");
            return RedirectToAction("Login");
        }

        #endregion



        #region Register

        [HttpGet]
        public IActionResult Register()
        {
            return View("register");
        }


        [HttpPost]
        public async Task<IActionResult> Register(RegisterVM registerVM)
        {
            if (!ModelState.IsValid)
            {
                return View(registerVM);
            }
            var response = await _httpClient.PostAsJsonAsync("/api/Account/register", registerVM);
            var errors = await ApiErrorHandler.HandleApiErrorAsync(response);

            if (errors.Count == 0)
            {
                TempData["Email"] = registerVM.Email;

                return RedirectToAction(nameof(ConfirmEmail));
            }
            foreach (var error in errors)
            {
                ModelState.AddModelError("", error);
            }
            return View(registerVM);

        }

        #endregion


        #region confirm email



        private async Task<bool> SendConfirmEmailCode(ConfirmEmailVM confirmEmailVM)
        {

            var response = await _httpClient.PostAsync($"/api/Account/SendConfirmEmailCode?email={confirmEmailVM.Email}", null);
            var errors = await ApiErrorHandler.HandleApiErrorAsync(response);
            return errors.Count == 0;
        }


        [HttpGet]
        public async Task<IActionResult> ConfirmEmail()
        {
            var email = TempData["Email"] as string;

            await SendConfirmEmailCode(new ConfirmEmailVM { Email = email });

            return View(new ConfirmEmailVM { Email = email });

        }


        [HttpPost]
        public async Task<IActionResult> ConfirmEmail(ConfirmEmailVM confirmEmailVM)
        {
            if (confirmEmailVM.Code == null)
            {
                ModelState.AddModelError("", "Please enter the code");
                return View(confirmEmailVM);
            }

            var url = $"/api/Account/ConfirmEmail?email={confirmEmailVM.Email}&code={confirmEmailVM.Code}";
            var response = await _httpClient.PostAsync(url, null);
            var errors = await ApiErrorHandler.HandleApiErrorAsync(response);
            if (errors.Count == 0)
            {
                return View("ConfirmEmailSuccess");
            }
            ModelState.AddModelError("", "Invalid Code");

            return View(confirmEmailVM);
        }


        #endregion


        #region Forget Password

        [HttpGet]
        public IActionResult ForgotPassword()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> SendResetLink(ForgotPasswordVM model)
        {
            if (!ModelState.IsValid)
            {
                return View("ForgotPassword", model);
            }

            var url = $"/api/Account/SendResetPasswordLink?email={model.Email}";
            var response = await _httpClient.PostAsync(url, null);
            var errors = await ApiErrorHandler.HandleApiErrorAsync(response);

            if (errors.Count == 0)
            {
                ViewBag.Message = "Reset link sent successfully. Please check your email.";
                return View("ForgotPassword");
            }


            ModelState.AddModelError("", "Something Went wrong,please try again");
            return View("ForgotPassword", model);

        }

        [HttpGet]
        public IActionResult ResetPassword(string email, string token)
        {
            var model = new ResetPasswordVM
            {
                Email = email,
                Token = token
            };
            return View(model);
        }


        [HttpPost]
        public async Task<IActionResult> ResetPassword(ResetPasswordVM resetPasswordVM)
        {
            if (!ModelState.IsValid)
            {
                return View(resetPasswordVM);
            }
            var response = await _httpClient.PostAsJsonAsync("/api/Account/ResetPassword", resetPasswordVM);
            var errors = await ApiErrorHandler.HandleApiErrorAsync(response);

            if (errors.Count == 0)
            {
                ViewBag.Message = "Password changed successfully";
                return View();
            }


            ModelState.AddModelError("", "Something Went wrong,please try again");
            return View(resetPasswordVM);
        }
        #endregion

    }
}

