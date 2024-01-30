using JobAgency.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc;
using JobAgency.Services;
using JobAgency.ViewModels;
using Microsoft.Extensions.Logging;

namespace JobAgency.Pages
{
    public class ResetPasswordModel : PageModel
    {
        private readonly UserManager<ApplicationUser> userManager;
        private readonly SignInManager<ApplicationUser> signInManager;
        private readonly IWebHostEnvironment webHostEnvironment;
        private readonly IEmailSender emailSender;
        private readonly AuthDbContext _context;
        private readonly ILogger<ResetPasswordModel> _logger;

        [BindProperty]
        public string VerificationCode { get; set; }
        [BindProperty]
        public string NewPassword { get; set; }
        [BindProperty]
        public string ConfirmPassword { get; set; }

        public ResetPasswordModel(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, IWebHostEnvironment webHostEnvironment, IEmailSender emailSender, AuthDbContext context, ILogger<ResetPasswordModel> logger)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
            this.webHostEnvironment = webHostEnvironment;
            this.emailSender = emailSender;
            _context = context;
            _logger = logger;
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (ModelState.IsValid)
            {
                var userId = TempData["UserId"]?.ToString();
                var verificationCode = TempData["VerificationCode"]?.ToString();

                if (!string.IsNullOrEmpty(userId) && !string.IsNullOrEmpty(verificationCode))
                {
                    var user = await userManager.FindByIdAsync(userId);

                    if (user != null)
                    {
                        // Check if the new password is in the password history
                        if (IsPasswordInHistory(user, NewPassword))
                        {
                            ModelState.AddModelError(string.Empty, "Password cannot be reused. Please choose a different password.");
                            return Page();
                        }

                        // Update user password
                        var result = await userManager.ResetPasswordAsync(user, verificationCode, NewPassword);

                        if (result.Succeeded)
                        {
                            // Password reset successful, send email confirmation
                            await SendPasswordChangeConfirmationEmail(user);

                            // Redirect to a confirmation page
                            _logger.LogInformation($"Password reset successfully for user {user.Id}.");
                            return RedirectToPage("/Login");
                        }
                        else
                        {
                            foreach (var error in result.Errors)
                            {
                                ModelState.AddModelError(string.Empty, error.Description);
                            }
                        }
                    }
                    else
                    {
                        ModelState.AddModelError(string.Empty, "Invalid user.");
                    }
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Invalid verification code or user ID.");
                }
            }

            return Page();
        }

        private async Task SendPasswordChangeConfirmationEmail(ApplicationUser user)
        {
            // Customize the email subject and body as needed
            var emailSubject = "Password Change Confirmation";
            var emailBody = "Your password has been successfully changed.";

            emailSender.SendEmail(user.Email, emailSubject, emailBody);
        }


        private bool IsPasswordInHistory(ApplicationUser user, string newPassword)
        {
            var passwordHistories = _context.PasswordChangeHistories
                .Where(h => h.UserId == user.Id)
                .OrderByDescending(h => h.ChangeDate)
                .Take(2)
                .ToList();

            if (passwordHistories != null)
            {
                return passwordHistories.Any(history =>
                    userManager.PasswordHasher.VerifyHashedPassword(null, history.PasswordHash, newPassword) !=
                    PasswordVerificationResult.Failed);
            }

            return false; // or handle it based on your logic
        }
    }
}
