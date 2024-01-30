// VerifyIdentity.cshtml.cs
using JobAgency.Model;
using JobAgency.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Threading.Tasks;

namespace JobAgency.Pages
{
    public class VerifyIdentityModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IEmailSender _emailSender;
        private readonly ILogger<VerifyIdentityModel> _logger; // Add ILogger for logging

        public VerifyIdentityModel(UserManager<ApplicationUser> userManager, IEmailSender emailSender, ILogger<VerifyIdentityModel> logger)
        {
            _userManager = userManager;
            _emailSender = emailSender;
            _logger = logger;
        }

        [BindProperty]
        public string Email { get; set; }

        [BindProperty]
        public string WhoAmI { get; set; }

        public IActionResult OnGet()
        {
            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(Email);

                if (user != null && user.WhoAmI == WhoAmI)
                {
                    // Authorization successful, generate and send verification code
                    var verificationCode = await _userManager.GeneratePasswordResetTokenAsync(user);

                    TempData["VerificationCode"] = verificationCode;
                    TempData["UserId"] = user.Id;

                    // Send email with the verification code
                    _emailSender.SendEmail(Email, "Verification Code", $"Your verification code is: {verificationCode}");

                    _logger.LogInformation($"Verification code generated for user {user.Id}: {verificationCode}");

                    return RedirectToPage("/ResetPassword");
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Invalid Email or Who Am I.");
                }
            }

            return Page();
        }
    }
}
