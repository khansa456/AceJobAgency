using System.ComponentModel.DataAnnotations;

namespace JobAgency.ViewModels
{
    public class Register
    {
        [Required]
        public string FirstName { get; set; }

        [Required]
        public string LastName { get; set; }

        [Required]
        public string Gender { get; set; }

        [Required]
        [RegularExpression(@"^[STFG]\d{7}[A-Z]$", ErrorMessage = "Invalid NRIC")]
        public string NRIC { get; set; }

        [Required]
        [DataType(DataType.EmailAddress)]
        public string Email { get; set; }

        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [Compare(nameof(Password), ErrorMessage = "Password and confirmation password do not match")]
        public string ConfirmPassword { get; set; }


        [Required]
        [DataType(DataType.Date)]
        [CustomDateOfBirth(ErrorMessage = "Invalid date of birth.")]
        public DateTime DateOfBirth { get; set; }

        [Required]
        [AllowedExtensions(new string[] { ".docx", ".pdf" }, ErrorMessage = "Invalid file format")]
        public IFormFile Resume { get; set; }

        [Required]
        [AllowSpecialCharacters(ErrorMessage = "Special characters are allowed")]
        public string WhoAmI { get; set; }
    }

    public class AllowSpecialCharactersAttribute : RegularExpressionAttribute
    {
        public AllowSpecialCharactersAttribute()
            : base(@"^[a-zA-Z0-9\s!@#$%^&*(),.?""\\:{}|<>]+$")
        {
        }
    }

    public class CustomDateOfBirthAttribute : ValidationAttribute
    {
        protected override ValidationResult IsValid(object value, ValidationContext validationContext)
        {
            if (value is DateTime dateTimeValue)
            {
                if (dateTimeValue == DateTime.MinValue)
                {
                    return new ValidationResult("Date of birth is required.");
                }

                if (dateTimeValue > DateTime.Now)
                {
                    return new ValidationResult("Date of birth cannot be in the future.");
                }
                // Add any other conditions you need
            }
            return ValidationResult.Success;
        }
    }

    public class AllowedExtensionsAttribute : ValidationAttribute
    {
        private readonly string[] _extensions;

        public AllowedExtensionsAttribute(string[] extensions)
        {
            _extensions = extensions;
        }

        protected override ValidationResult IsValid(object value, ValidationContext validationContext)
        {
            if (value is IFormFile file)
            {
                var extension = Path.GetExtension(file.FileName);

                if (file.Length > 0 && !_extensions.Contains(extension.ToLower()))
                {
                    return new ValidationResult(GetErrorMessage());
                }
            }

            return ValidationResult.Success;
        }

        private string GetErrorMessage()
        {
            return $"Allowed file extensions are: {string.Join(", ", _extensions)}";
        }
    }
}
