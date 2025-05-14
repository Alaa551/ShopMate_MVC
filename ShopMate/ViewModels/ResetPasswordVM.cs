using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;
namespace ShopMate.ViewModels
{
    public class ResetPasswordVM
    {
        [Required(ErrorMessage = "*")]
        [EmailAddress(ErrorMessage = "Invalid email format")]
        [Remote(action: "DoesEmailExist", "Account", ErrorMessage = "This Email Doesn't Exist")]
        public string? Email { get; set; }


        [Display(Name = "New Password")]
        [DataType(DataType.Password)]
        [Required(ErrorMessage = "*")]
        public string? NewPassword { get; set; }


        [Display(Name = "Confirm Password")]
        [DataType(DataType.Password)]
        [Required(ErrorMessage = "*")]
        [Compare("NewPassword")]

        public string? ConfirmPassword { get; set; }

        public string Token { get; set; }


    }
}
