using JobAgency.ViewModels;
using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace JobAgency.Model
{
    public class AuthDbContext : IdentityDbContext<ApplicationUser>
    {
        public DbSet<PasswordChangeHistory> PasswordChangeHistories { get; set; }
        public DbSet<AuditLog> AuditLogEntries { get; set; }
        public DbSet<UserSession> UserSessions { get; set; }

        private readonly IConfiguration _configuration;

        public AuthDbContext(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            string connectionString = _configuration.GetConnectionString("AceConnectionString");
            optionsBuilder.UseSqlServer(connectionString);
        }
    }
}
