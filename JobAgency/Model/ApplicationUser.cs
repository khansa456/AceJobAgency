using JobAgency.ViewModels;
using Microsoft.AspNetCore.Identity;

namespace JobAgency.Model
{
    public class ApplicationUser : IdentityUser
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Gender { get; set; }
        public string NRIC { get; set; }
        public DateTime DateOfBirth { get; set; }
        public string Password { get; set; }
        public byte[] ResumeContent { get; set; }
        public string ResumeFileName { get; set; }
        public string WhoAmI { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime? LastPasswordChangeDate { get; set; }
        public DateTime? PasswordExpirationDate { get; set; }
        public ICollection<PasswordChangeHistory> PasswordChangeHistories { get; set; }
        [PersonalData]
        public bool LockoutEnabled { get; set; } = true;
    }
}
