using JobAgency.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Newtonsoft.Json;
using System.Net;
using System.Text.RegularExpressions;
using JobAgency.Model;
using Microsoft.AspNetCore.DataProtection;
using JobAgency.Services;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Html;


namespace JobAgency.Pages
{
    public class MyObject
    {
        public bool success { get; set; }
    }

    public class RegisterModel : PageModel
    {
        private readonly UserManager<ApplicationUser> userManager;
        private readonly SignInManager<ApplicationUser> signInManager;
        private readonly IWebHostEnvironment webHostEnvironment;
        private readonly IEmailSender emailSender;
        private readonly AuthDbContext _context;
        private readonly HtmlEncoder htmlEncoder;

        [BindProperty]
        public Register RModel { get; set; }

        public RegisterModel(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, IWebHostEnvironment webHostEnvironment, IEmailSender emailSender, AuthDbContext context)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
            this.webHostEnvironment = webHostEnvironment;
            this.emailSender = emailSender;
            this.htmlEncoder = htmlEncoder;
            _context = context;
        }

        public void OnGet()
        {
            // Retrieve the user from the database
            //var user = userManager.GetUserAsync(User).Result;

            // Decrypt the NRIC
            //string decryptedNRIC = DecryptNRIC(user.NRIC);
        }

        [ValidateAntiForgeryToken]
        public async Task<IActionResult> OnPostAsync()
        {
            HttpContext.Session.Clear();
            Response.Cookies.Delete(".AspNetCore.Session");
            Response.Cookies.Delete(".AspNetCore.Identity.Application");
            if (ModelState.IsValid)
            {
                if (!IsPasswordStrong(RModel.Password))
                {
                    ModelState.AddModelError("RModel.Password", "Password must be 12 to 18 characters long and include at least one uppercase letter, one lowercase letter, one digit, and one special character.");
                    return Page();
                }
                if (!IsValidEmail(RModel.Email))
                {
                    ModelState.AddModelError("RModel.Email", "Invalid email address.");
                    return Page();
                }
                var isCaptchaValid = ValidateCaptcha();
                if (!isCaptchaValid)
                {
                    ModelState.AddModelError("", "reCAPTCHA validation failed. Please try again.");
                    return Page();
                }
                var dataProtectionProvider = DataProtectionProvider.Create("EncryptData");
                var protector = dataProtectionProvider.CreateProtector("MySecret");


                var user = new ApplicationUser()
                {
                    UserName = RModel.Email,
                    Email = RModel.Email,
                    FirstName = RModel.FirstName,
                    LastName = RModel.LastName,
                    Gender = RModel.Gender,
                    NRIC = protector.Protect(RModel.NRIC),
                    Password = RModel.Password,
                    DateOfBirth = RModel.DateOfBirth,
                    ResumeContent = ReadFileContent(RModel.Resume),
                    ResumeFileName = RModel.Resume.FileName,
                    WhoAmI = RModel.WhoAmI,
                    CreatedAt = DateTime.UtcNow,
                    LastPasswordChangeDate = DateTime.UtcNow,
                    PasswordExpirationDate = DateTime.UtcNow.AddMonths(1)
                };

                var result = await userManager.CreateAsync(user, RModel.Password);
                if (result.Succeeded)
                {
                    await signInManager.SignInAsync(user, false);

                    // Create initial password history
                    await CreateInitialPasswordHistory(user);

                    // Send welcome email
                    string welcomeEmailSubject = "Welcome to Job Agency";
                    string welcomeEmailBody = $"<h1>Welcome to Job Agency</h1><p>Thank you for registering your account, {HtmlEncoder.Default.Encode(user.UserName)}.</p>";
                    emailSender.SendEmail(user.Email, welcomeEmailSubject, welcomeEmailBody);

                    return RedirectToPage("/Login");
                }

                foreach (var error in result.Errors)
                {
                    if (error.Code == "DuplicateUserName" || error.Code == "DuplicateEmail")
                    {
                        ModelState.AddModelError("RModel.Email", "Email address is already in use.");
                    }
                    else
                    {
                        ModelState.AddModelError("", error.Description);
                    }
                }
            }
            return Page();
        }
        
        private bool IsPasswordStrong(string password)
        {
            // Regex for at least 12 characters, at most 18 characters,
            // with at least one uppercase, one lowercase, one digit, and one special character
            const string passwordPattern = @"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{12,18}$";
            return Regex.IsMatch(password, passwordPattern);
        }

        private bool IsValidEmail(string email)
        {
            try
            {
                var addr = new System.Net.Mail.MailAddress(email);
                return addr.Address == email && email.Contains('@');
            }
            catch
            {
                return false;
            }
        }

        private byte[] ReadFileContent(IFormFile file)
        {
            using (var memoryStream = new MemoryStream())
            {
                file.CopyTo(memoryStream);
                return memoryStream.ToArray();
            }
        }

        private async Task CreateInitialPasswordHistory(ApplicationUser user)
        {
            var initialPasswordHistory = new PasswordChangeHistory
            {
                UserId = user.Id,
                ChangeDate = user.CreatedAt, // Assuming you have a property indicating user creation date
                PasswordHash = user.PasswordHash  // Store the initial password hash
            };

            _context.PasswordChangeHistories.Add(initialPasswordHistory);
            await _context.SaveChangesAsync();
        }

        public bool ValidateCaptcha()
        {
            string response = Request.Form["g-recaptcha-response"];

            // Request to Google Server for reCAPTCHA validation
            HttpWebRequest req = (HttpWebRequest)WebRequest.Create($"https://www.google.com/recaptcha/api/siteverify?secret=6LdUuzspAAAAAAJ3t3GfbG87bJ7G-JQMRE-zdIw7&response={response}");

            try
            {
                using (WebResponse wResponse = req.GetResponse())
                {
                    using (StreamReader readStream = new StreamReader(wResponse.GetResponseStream()))
                    {
                        string jsonResponse = readStream.ReadToEnd();
                        var data = JsonConvert.DeserializeObject<MyObject>(jsonResponse); // Deserialize JSON
                        return data.success;
                    }
                }
            }
            catch (WebException ex)
            {
                throw ex;
            }
        }








    }
}
