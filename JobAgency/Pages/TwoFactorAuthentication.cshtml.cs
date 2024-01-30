using JobAgency.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc;

namespace JobAgency.Pages
{
    public class TwoFactorAuthenticationModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> signInManager;
        private readonly UserManager<ApplicationUser> userManager;
        private readonly AuthDbContext dbContext;
        private readonly ILogger<TwoFactorAuthenticationModel> _logger;

        public TwoFactorAuthenticationModel(
            SignInManager<ApplicationUser> signInManager,
            UserManager<ApplicationUser> userManager,
            AuthDbContext dbContext,
            ILogger<TwoFactorAuthenticationModel> logger)
        {
            this.signInManager = signInManager;
            this.userManager = userManager;
            this.dbContext = dbContext;
            _logger = logger;
        }

        public IActionResult OnGet()
        {
            return Page();
        }

        public async Task<IActionResult> OnPostAsync(string verificationCode, string returnUrl)
        {
            var user = await userManager.GetUserAsync(User);

            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{userManager.GetUserId(User)}'.");
            }

            // Cleanup expired sessions before checking for an existing session
            await CleanupExpiredSessions(user.Id);

            // Check for an existing session with a valid SessionId
            var existingSession = dbContext.UserSessions
                .Where(s => s.UserId == user.Id && !string.IsNullOrEmpty(s.SessionId))
                .FirstOrDefault();

            if (existingSession != null)
            {
                // Redirect the user to the login page if there is an active session
                _logger.LogInformation($"User {user.Id} already has an active session. Redirecting to login page.");
                return RedirectToPage("/Login");
            }

            // Generate a unique SessionId
            var uniqueSessionId = Guid.NewGuid().ToString();

            // Store UserId, SessionId, and ExpirationTime in the database
            var userSession = new UserSession
            {
                UserId = user.Id,
                SessionId = uniqueSessionId,
                CreatedAt = DateTime.Now,
                ExpirationTime = DateTime.Now.AddMinutes(2) // Set the expiration time to 20 minutes
            };

            dbContext.UserSessions.Add(userSession);
            await dbContext.SaveChangesAsync();

            var isCodeValid = await userManager.VerifyTwoFactorTokenAsync(user, "Email", verificationCode);

            if (isCodeValid)
            {
                // Sign in the user
                await signInManager.SignInAsync(user, isPersistent: false);

                // Set EmailConfirmed to true
                user.EmailConfirmed = true;
                await userManager.UpdateAsync(user);

                await userManager.SetTwoFactorEnabledAsync(user, true);

                _logger.LogInformation($"User {user.Id} logged in with 2FA successfully.");

                return Redirect("/Index");
            }
            else
            {
                ModelState.AddModelError("verificationCode", "Incorrect verification code.");
                return Page();
            }
        }

        private async Task CleanupExpiredSessions(string userId)
        {
            var expiredSessions = dbContext.UserSessions
                .Where(s => s.UserId == userId && s.ExpirationTime <= DateTime.Now)
                .ToList();

            foreach (var expiredSession in expiredSessions)
            {
                dbContext.UserSessions.Remove(expiredSession);
            }

            await dbContext.SaveChangesAsync();

            _logger.LogInformation($"Cleaned up {expiredSessions.Count} expired sessions for user {userId}.");
        }
    }
}