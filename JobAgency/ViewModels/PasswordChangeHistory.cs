using JobAgency.Model;

namespace JobAgency.ViewModels
{
    public class PasswordChangeHistory
    {
        public int Id { get; set; }
        public string UserId { get; set; }
        public DateTime ChangeDate { get; set; }
        public string PasswordHash { get; set; }
        public ApplicationUser User { get; set; }
    }

}
