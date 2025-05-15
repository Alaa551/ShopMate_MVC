using System.ComponentModel.DataAnnotations;

namespace ShopMate.ViewModels
{
    public class ConfirmEmailVM
    {
        [Required]
        public string? Email { get; set; }

        [Display(Name = "Confirmation Code")]
        public string? Code { get; set; }
    }
}
