using ShopMate.Enums;
using System.ComponentModel.DataAnnotations;
namespace ShopMate.ViewModels
{
	public class RegisterVM
	{
		[Required(ErrorMessage = "*")]
		[Display(Name = "First Name")]

		public string? FirstName { get; set; }

		[Required(ErrorMessage = "*")]
		[Display(Name = "Last Name")]
		public string? LastName { get; set; }

		[Required(ErrorMessage = "*")]
		public string? UserName { get; set; }


		[Required(ErrorMessage = "*")]
		[EmailAddress(ErrorMessage = "Invalid email format")]
		public string? Email { get; set; }


		[DataType(DataType.Password)]
		[Required(ErrorMessage = "*")]
		public string? Password { get; set; }


		[Display(Name = "Confirm Password")]
		[DataType(DataType.Password)]
		[Required(ErrorMessage = "*")]
		[Compare("Password")]

		public string? ConfirmPassword { get; set; }

		[Display(Name = "Phone Number")]
		[DataType(DataType.PhoneNumber)]
		[Required(ErrorMessage = "*")]
		[StringLength(11, MinimumLength = 11, ErrorMessage = "Phone number must be 11 numbers")]
		public string? PhoneNumber { get; set; }

		[Display(Name = "Remember Me")]
		public bool RememberMe { get; set; }

		public IFormFile? ProfileImage { get; set; }

		[Required(ErrorMessage = "*")]
		public string? Address { get; set; }

		public Gender Gender { get; set; }
	}

}
