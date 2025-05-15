using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ShopMate.ViewModels;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace PL.Controllers
{
    public class AccountController : Controller
    {
        private readonly HttpClient _httpClient;
        private readonly string _apiBaseUrl;

        public AccountController(HttpClient httpClient)
        {
            _httpClient = httpClient;
            _httpClient.BaseAddress = new Uri("https://localhost:7012");
            _apiBaseUrl = "https://localhost:7012";

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
                storeToken(token);
                await SignInUserAsync(loginVM.RememberMe, token);
                return RedirectToAction("Index", "Home");
            }
            foreach (var error in errors)
            {
                ModelState.AddModelError("", error);
            }
            return View(loginVM);
        }


        private void storeToken(string token)
        {
            HttpContext.Response.Cookies.Append("JWToken", token, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                Expires = DateTimeOffset.UtcNow.AddDays(1),
                IsEssential = true
            });
        }
        private async Task SignInUserAsync(bool rememberMe, string token)
        {
            var handler = new JwtSecurityTokenHandler();

            var jwtToken = handler.ReadJwtToken(token);

            IList<Claim> claims = jwtToken.Claims.ToList();

            var imageClaim = claims.FirstOrDefault(c => c.Type == "ProfileImagePath");
            if (imageClaim != null)
            {
                claims.Add(new Claim("FullProfileImageUrl", $"{_apiBaseUrl}{imageClaim.Value}"));
            }
            var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            var principal = new ClaimsPrincipal(identity);

            await HttpContext.SignInAsync(
                   CookieAuthenticationDefaults.AuthenticationScheme,
                   principal,
                   new AuthenticationProperties
                   {
                       IsPersistent = rememberMe,
                       ExpiresUtc = DateTime.UtcNow.AddHours(24)
                   }
               );
        }


        [HttpGet]
        public async Task<IActionResult> LogoutAsync()
        {
            if (Request.Cookies["JWToken"] != null)
            {
                Response.Cookies.Delete("JWToken");
            }
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
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
            var formData = BuildRegisterFormData(registerVM);

            var response = await _httpClient.PostAsync("/api/Account/register", formData);
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

        private MultipartFormDataContent BuildRegisterFormData(RegisterVM model)
        {
            var formData = new MultipartFormDataContent();

            if (model.ProfileImage != null)
            {
                var stream = model.ProfileImage.OpenReadStream();
                var fileContent = new StreamContent(stream);
                fileContent.Headers.ContentType = new MediaTypeHeaderValue(model.ProfileImage.ContentType);
                formData.Add(fileContent, "ProfileImage", model.ProfileImage.FileName);
            }

            formData.Add(new StringContent(model.FirstName ?? ""), "FirstName");
            formData.Add(new StringContent(model.LastName ?? ""), "LastName");
            formData.Add(new StringContent(model.UserName ?? ""), "UserName");
            formData.Add(new StringContent(model.Email ?? ""), "Email");
            formData.Add(new StringContent(model.Password ?? ""), "Password");
            formData.Add(new StringContent(model.ConfirmPassword ?? ""), "ConfirmPassword");
            formData.Add(new StringContent(model.PhoneNumber ?? ""), "PhoneNumber");
            formData.Add(new StringContent(model.Address ?? ""), "Address");
            formData.Add(new StringContent(model.RememberMe.ToString()), "RememberMe");
            formData.Add(new StringContent(model.Gender.ToString()), "Gender");

            return formData;
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


        #region profile
        [HttpPost]
        [Authorize]
        public async Task<IActionResult> UpdateProfile(ProfileVM profileVM)
        {
            if (!ModelState.IsValid)
            {
                return View("Profile", profileVM);
            }
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            profileVM.UserId = userId;

            var token = HttpContext.Request.Cookies["JWToken"];
            if (string.IsNullOrEmpty(token))
                return RedirectToAction("Login", "Account");

            var formData = BuildUpdateProfileFormData(profileVM);

            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await _httpClient.PutAsync("/api/Account/Profile", formData);
            var errors = await ApiErrorHandler.HandleApiErrorAsync(response);

            if (errors.Count == 0)
            {
                var options = new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true,
                    Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
                };
                var updatedProfile = await response.Content.ReadFromJsonAsync<ProfileVM>(options);

                await UpdateUserClaims(updatedProfile);

                ViewBag.Message = "Profile updated successfully.";
                return RedirectToAction(nameof(Profile));
            }

            ViewBag.Message = "Something went worng, please try again";
            return View("Profile", profileVM);
        }

        private MultipartFormDataContent BuildUpdateProfileFormData(ProfileVM profileVM)
        {
            var formData = new MultipartFormDataContent();

            if (profileVM.ProfileImage != null && profileVM.ProfileImage.Length > 0)
            {
                var fileContent = new StreamContent(profileVM.ProfileImage.OpenReadStream());
                fileContent.Headers.ContentType = new MediaTypeHeaderValue(profileVM.ProfileImage.ContentType);
                formData.Add(fileContent, "ProfileImage", profileVM.ProfileImage.FileName);
            }

            formData.Add(new StringContent(profileVM.UserId ?? ""), "Id");
            formData.Add(new StringContent(profileVM.FirstName ?? ""), "FirstName");
            formData.Add(new StringContent(profileVM.LastName ?? ""), "LastName");
            formData.Add(new StringContent(profileVM.Gender.ToString()), "Gender");
            formData.Add(new StringContent(profileVM.Email ?? ""), "Email");
            formData.Add(new StringContent(profileVM.Address ?? ""), "Address");
            formData.Add(new StringContent(profileVM.PhoneNumber ?? ""), "PhoneNumber");

            return formData;
        }

        public async Task<IActionResult> Profile()
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var token = HttpContext.Request.Cookies["JWToken"];

            if (string.IsNullOrEmpty(token))
            {
                return View();
            }

            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);


            var url = $"/api/Account/Profile?userId={userId}";
            var response = await _httpClient.GetAsync(url);
            var errors = await ApiErrorHandler.HandleApiErrorAsync(response);

            if (errors.Count == 0)
            {
                var options = new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true,
                    Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
                };
                var profile = await response.Content.ReadFromJsonAsync<ProfileVM>(options);
                profile.ProfileImagePath = $"{_apiBaseUrl}{profile.ProfileImagePath}";


                return View(profile);
            }

            return View();

        }

        private async Task UpdateUserClaims(ProfileVM profileVM)
        {
            var identity = User.Identity as ClaimsIdentity;

            if (identity == null) return;

            var oldImageClaim = identity.FindFirst("FullProfileImageUrl");
            if (oldImageClaim != null)
                identity.RemoveClaim(oldImageClaim);

            var fullUrl = $"{_apiBaseUrl}{profileVM.ProfileImagePath}";
            identity.AddClaim(new Claim("FullProfileImageUrl", fullUrl));


            var principal = new ClaimsPrincipal(identity);

            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);
        }
        #endregion

        #region Change Password

        [HttpGet]
        public IActionResult ChangePassword()
        {
            return View();
        }


        [HttpPost]
        public async Task<IActionResult> ChangePassword(ChangePasswordVM changePasswordVM)
        {

            if (!ModelState.IsValid)
            {
                return View(changePasswordVM);
            }
            var token = HttpContext.Request.Cookies["JWToken"];

            if (string.IsNullOrEmpty(token))
            {
                ViewBag.Message = "Unauthorized: Session token not found.";
                return View(changePasswordVM);
            }

            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await _httpClient.PostAsJsonAsync("/api/Account/ChangePassword", changePasswordVM);

            var errors = await ApiErrorHandler.HandleApiErrorAsync(response);

            if (errors.Count == 0)
            {
                ViewBag.Message = "Password changed successfully";
                return View();
            }

            foreach (var error in errors)
            {
                ModelState.AddModelError("", error);
            }
            return View(changePasswordVM);
        }

        #endregion



        #region Access Denied
        [HttpGet]
        public IActionResult AccessDenied()
        {

            return View();
        }
        #endregion


    }
}

