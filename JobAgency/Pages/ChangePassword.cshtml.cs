using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using JobAgency.Model;
using JobAgency.Services;
using JobAgency.ViewModels;

namespace JobAgency.Pages
{
    public class ChangePassword
    {
        public string OldPassword { get; set; }
        public string NewPassword { get; set; }
        public string ConfirmPassword { get; set; }
    }

    [AuthorizeSession]
    public class ChangePasswordModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IEmailSender _emailSender;
        private readonly AuthDbContext _context;

        public ChangePasswordModel(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, IEmailSender emailSender, AuthDbContext context)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _emailSender = emailSender;
            _context = context;
        }

        [BindProperty]
        public ChangePassword CModel { get; set; }

        public async Task<IActionResult> OnPostAsync()
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.GetUserAsync(User);
                if (user == null)
                {
                    return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
                }

                // Check if the old password is correct
                var isOldPasswordCorrect = await _userManager.CheckPasswordAsync(user, CModel.OldPassword);
                if (!isOldPasswordCorrect)
                {
                    ModelState.AddModelError(string.Empty, "Old password is incorrect.");
                    return Page();
                }

                // Check if new password and confirm password match
                if (CModel.NewPassword != CModel.ConfirmPassword)
                {
                    ModelState.AddModelError(string.Empty, "New password and confirm password do not match.");
                    return Page();
                }

                // Check if the password change is allowed based on minimum and maximum age
                var passwordChangeAllowed = IsPasswordChangeAllowed(user);
                if (!passwordChangeAllowed)
                {
                    ModelState.AddModelError(string.Empty, "Password change is not allowed within the specified timeframe.");
                    return Page();
                }

                // Check if the new password is not in the user's password history
                var isPasswordInHistory = IsPasswordInHistory(user, CModel.NewPassword);
                if (isPasswordInHistory)
                {
                    ModelState.AddModelError(string.Empty, "Password has been used recently and cannot be reused.");
                    return Page();
                }

                var changePasswordResult = await _userManager.ChangePasswordAsync(user, CModel.OldPassword, CModel.NewPassword);

                if (changePasswordResult.Succeeded)
                {
                    // Update the last password change date
                    user.LastPasswordChangeDate = DateTime.UtcNow;

                    // Store password change history
                    var passwordChangeHistory = new PasswordChangeHistory
                    {
                        UserId = user.Id,
                        ChangeDate = DateTime.UtcNow,
                        PasswordHash = user.PasswordHash  // Store the new password hash
                    };

                    if (user.PasswordChangeHistories == null)
                    {
                        user.PasswordChangeHistories = new List<PasswordChangeHistory>();
                    }

                    user.PasswordChangeHistories.Add(passwordChangeHistory);

                    await _userManager.UpdateAsync(user);

                    // Send confirmation email
                    var emailSubject = "Password Change Confirmation";
                    var emailBody = "Your password has been successfully changed.";

                    _emailSender.SendEmail(user.Email, emailSubject, emailBody);

                    // Refresh sign-in
                    await _signInManager.RefreshSignInAsync(user);

                    // Redirect to the confirmation page or any other page
                    return RedirectToPage("/Index");
                }

                foreach (var error in changePasswordResult.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
            }

            return Page();
        }

        private bool IsPasswordChangeAllowed(ApplicationUser user)
        {
            // Implement your logic here based on minimum and maximum password age
            var minPasswordAge = TimeSpan.FromMinutes(15); // Example: 15 minutes
            var maxPasswordAge = TimeSpan.FromDays(30); // Example: 30 days

            if (user.LastPasswordChangeDate.HasValue)
            {
                var timeSinceLastChange = DateTime.UtcNow - user.LastPasswordChangeDate.Value;

                if (timeSinceLastChange < minPasswordAge || timeSinceLastChange > maxPasswordAge)
                {
                    return false;
                }
            }

            return true;
        }

        private bool IsPasswordInHistory(ApplicationUser user, string newPassword)
        {
            // Retrieve password change histories for the user
            var passwordHistories = _context.PasswordChangeHistories
                .Where(h => h.UserId == user.Id)
                .OrderByDescending(h => h.ChangeDate)
                .Take(2)
                .ToList();

            if (passwordHistories != null)
            {
                // Check if the new password matches any of the previous passwords
                var isPasswordInHistory = passwordHistories.Any(history =>
                    _userManager.PasswordHasher.VerifyHashedPassword(null, history.PasswordHash, newPassword) != PasswordVerificationResult.Failed);

                if (isPasswordInHistory)
                {
                    user.PasswordExpirationDate = DateTime.UtcNow.AddMonths(1); // Example: Password expires in 1 month
                }

                return isPasswordInHistory;
            }

            return false; // or handle it based on your logic
        }
    }
}

