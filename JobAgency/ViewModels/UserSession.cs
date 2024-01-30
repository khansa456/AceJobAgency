using System.ComponentModel.DataAnnotations;

namespace JobAgency.Model
{
    public class UserSession
    {
        [Key]
        public int Id { get; set; }
        public string UserId { get; set; }
        public string SessionId { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime ExpirationTime { get; set; }
    }
}

