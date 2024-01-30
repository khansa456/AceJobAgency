using JobAgency.Model;
using JobAgency.Services;
using JobAgency.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;


namespace JobAgency.Pages
{
    public class LoginModel : PageModel
    {
        [BindProperty]
        public Login LModel { get; set; }

        private readonly SignInManager<ApplicationUser> signInManager;
        private readonly UserManager<ApplicationUser> userManager;
        private readonly ILogger<LoginModel> _logger;
        private readonly AuthDbContext _context;
        private readonly IEmailSender emailSender;

        public LoginModel(
            SignInManager<ApplicationUser> signInManager,
            UserManager<ApplicationUser> userManager,
            ILogger<LoginModel> logger,
            AuthDbContext context,
            IEmailSender emailSender)
        {
            this.signInManager = signInManager;
            this.userManager = userManager;
            _logger = logger;
            _context = context;
            this.emailSender = emailSender;
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (ModelState.IsValid)
            {
                var sanitizedEmail = HtmlEncoder.Default.Encode(LModel.Email);
                var sanitizedPassword = HtmlEncoder.Default.Encode(LModel.Password);

                var result = await signInManager.PasswordSignInAsync(sanitizedEmail, sanitizedPassword, LModel.RememberMe, false);

                var auditLog = new AuditLog
                {
                    Timestamp = DateTime.UtcNow,
                    Action = "Login Attempt",
                    Details = $"Login attempt for email: {HtmlEncoder.Default.Encode(LModel.Email)}"
                };

                if (result.Succeeded)
                {
                    var user = await userManager.FindByEmailAsync(LModel.Email);

                    // Reset the access failed count upon successful login
                    await userManager.ResetAccessFailedCountAsync(user);

                    // Log UserId when successful login
                    _logger.LogInformation($"User {user.Id} logged in successfully.");

                    auditLog.UserId = user.Id;
                    auditLog.Details += " - Successful";

                    // Check if the password has expired
                    if (user.PasswordExpirationDate.HasValue && user.PasswordExpirationDate < DateTime.UtcNow)
                    {
                        // Password has expired, redirect to the password reset page
                        return RedirectToPage("/VerifyIdentity");
                    }

                    var token = await userManager.GenerateTwoFactorTokenAsync(user, "Email");
                    HttpContext.Session.SetString("TwoFactorToken", token);

                    // Send the token to the user via email using your EmailSender service
                    var emailBody = $"Your 2FA code is: {token}";
                    emailSender.SendEmail(user.Email, "Your 2FA Code", emailBody);

                    // Redirect to TwoFactorAuthentication page
                    return RedirectToPage("/TwoFactorAuthentication", new { returnUrl = "/Index" });
                }

                else if (result.IsLockedOut)
                {
                    auditLog.Details += " - Account Locked Out";
                    _context.AuditLogEntries.Add(auditLog);
                    await _context.SaveChangesAsync();

                    ModelState.AddModelError("", "Account is locked out. Please try again later.");
                    _logger.LogWarning($"User {LModel.Email} is locked out.");
                }
                else
                {
                    ModelState.AddModelError("", "Username or Password incorrect");
                    _logger.LogWarning($"Failed login attempt for user {LModel.Email}.");
                    LModel.Email = null;
                    LModel.Password = null;
                }
            }

            return Page();
        }
    }
}
