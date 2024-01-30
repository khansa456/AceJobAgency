using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Identity;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using JobAgency.Model;
using Microsoft.AspNetCore.Antiforgery;
using System.Security.Claims;
using JobAgency.Services;

namespace JobAgency.Pages
{
    [AuthorizeSession]
    public class LogoutModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IAntiforgery _antiforgery;
        private readonly AuthDbContext _dbContext;

        public LogoutModel(SignInManager<ApplicationUser> signInManager, IAntiforgery antiforgery, AuthDbContext dbContext)
        {
            _signInManager = signInManager;
            _antiforgery = antiforgery;
            _dbContext = dbContext;
        }

        public async Task<IActionResult> OnPost()
        {
            var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            // Remove the user's session from the database
            var userSession = _dbContext.UserSessions
                .Where(s => s.UserId == currentUserId)
                .FirstOrDefault();

            if (userSession != null)
            {
                _dbContext.UserSessions.Remove(userSession);
                await _dbContext.SaveChangesAsync();
            }

            // Sign out the user
            await _signInManager.SignOutAsync();

            // Clear existing session keys
            HttpContext.Session.Clear();
            Response.Cookies.Delete(".AspNetCore.Session");
            Response.Cookies.Delete(".AspNetCore.Identity.Application");

            // Regenerate anti-forgery token
            var tokens = _antiforgery.GetAndStoreTokens(HttpContext);
            ViewData["RequestVerificationToken"] = tokens.RequestToken;

            // Redirect to the login page
            return RedirectToPage("/Login");
        }
    }
}

