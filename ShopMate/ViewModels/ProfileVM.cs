using ShopMate.Enums;
using System.ComponentModel.DataAnnotations;

namespace ShopMate.ViewModels
{
    public class ProfileVM
    {
        public string? UserId { get; set; }

        [Required(ErrorMessage = "*")]
        [Display(Name = "First Name")]

        public string? FirstName { get; set; }

        [Required(ErrorMessage = "*")]
        [Display(Name = "Last Name")]
        public string? LastName { get; set; }


        public string? UserName { get; set; }


        [Required(ErrorMessage = "*")]
        [EmailAddress(ErrorMessage = "Invalid email format")]

        public string? Email { get; set; }

        [Display(Name = "Phone Number")]
        [DataType(DataType.PhoneNumber)]
        [Required(ErrorMessage = "*")]
        public string? PhoneNumber { get; set; }


        public string? ProfileImagePath { get; set; }
        public IFormFile? ProfileImage { get; set; }

        [Required(ErrorMessage = "*")]
        public string? Address { get; set; }
        public Gender Gender { get; set; }

    }
}
