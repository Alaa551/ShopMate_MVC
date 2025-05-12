using System.ComponentModel.DataAnnotations;

namespace ShopMate.ViewModels
{
    public class LoginVM
    {
        [Required(ErrorMessage = "*")]
        [EmailAddress(ErrorMessage = "Invalid email format")]
        public string? Email { get; set; }

        [DataType(DataType.Password)]
        [Required(ErrorMessage = "*")]
        public string? Password { get; set; }

        [Display(Name = "Remember Me")]
        public bool RememberMe { get; set; }
    }
}
