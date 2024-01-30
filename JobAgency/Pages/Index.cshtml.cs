using JobAgency.Model;
using JobAgency.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using System.Security.Claims;

namespace JobAgency.Pages
{
    [AuthorizeSession]
    public class IndexModel : PageModel
    {
        private readonly ILogger<IndexModel> _logger;
        private readonly AuthDbContext dbContext;
        private readonly UserManager<ApplicationUser> userManager;

        public IndexModel(ILogger<IndexModel> logger, AuthDbContext dbContext, UserManager<ApplicationUser> userManager)
        {
            _logger = logger;
            this.dbContext = dbContext;
            this.userManager = userManager;
        }

        public async Task<IActionResult> OnGet()
        {
            var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            // Cleanup expired sessions before checking for active sessions
            await CleanupExpiredSessions(currentUserId);

            var activeSessions = dbContext.UserSessions
                .Where(s => s.UserId == currentUserId && s.ExpirationTime > DateTime.Now)
                .OrderByDescending(s => s.CreatedAt)
                .ToList();

            _logger.LogInformation($"CurrentUserId: {currentUserId}, ActiveSessionsCount: {activeSessions.Count}");

            if (activeSessions.Count > 1)
            {
                // Multiple logins detected, log the information
                _logger.LogInformation($"Multiple logins detected for user {currentUserId}. ActiveSessionsCount: {activeSessions.Count}");

                // Cleanup expired sessions again after logging the information
                await CleanupExpiredSessions(currentUserId);

                return RedirectToPage("/Login");
            }

            var user = await userManager.FindByIdAsync(currentUserId);

            // Decrypt the NRIC
            var dataProtectionProvider = DataProtectionProvider.Create("EncryptData");
            var protector = dataProtectionProvider.CreateProtector("MySecret");
            string decryptedNRIC = protector.Unprotect(user.NRIC);

            // You can now access all attributes and display them in your Index page
            ViewData["FirstName"] = user.FirstName;
            ViewData["LastName"] = user.LastName;
            ViewData["Gender"] = user.Gender;
            ViewData["NRIC"] = decryptedNRIC;
            ViewData["DateOfBirth"] = user.DateOfBirth.ToString("yyyy-MM-dd");
            ViewData["Email"] = user.Email;
            ViewData["ResumeFileName"] = user.ResumeFileName;
            //how to show content?
            //for the password, only show 5 *
            ViewData["WhoAmI"] = user.WhoAmI;

            return Page();
        }

        private async Task CleanupExpiredSessions(string userId)
        {
            var expiredSessions = dbContext.UserSessions
                .Where(s => s.UserId == userId && s.ExpirationTime <= DateTime.Now)
                .ToList();

            foreach (var expiredSession in expiredSessions)
            {
                // Remove from the database
                dbContext.UserSessions.Remove(expiredSession);

                // Remove from the ASP.NET Core session
                HttpContext.Session.Remove(expiredSession.SessionId);

                // Remove cookies (adjust the cookie names as per your application)
                Response.Cookies.Delete(".AspNetCore.Session");
                Response.Cookies.Delete(".AspNetCore.Identity.Application");
            }

            await dbContext.SaveChangesAsync();

            _logger.LogInformation($"Cleaned up {expiredSessions.Count} expired sessions for user {userId}.");
        }
    }
}
