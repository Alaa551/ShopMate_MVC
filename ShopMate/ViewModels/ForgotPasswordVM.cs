using System.ComponentModel.DataAnnotations;
namespace ShopMate.ViewModels
{
    public class ForgotPasswordVM
    {
        [Required(ErrorMessage = "*")]
        [EmailAddress(ErrorMessage = "Invalid email format")]

        public string? Email { get; set; }
    }
}
