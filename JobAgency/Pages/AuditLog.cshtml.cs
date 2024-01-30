using JobAgency.Model;
using JobAgency.ViewModels;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace JobAgency.Pages
{
    public class AuditLogModel : PageModel
    {
        private readonly AuthDbContext _context;

        public IList<AuditLog> AuditLogEntries { get; set; }

        public AuditLogModel(AuthDbContext context)
        {
            _context = context;
        }

        public async Task OnGetAsync()
        {
            AuditLogEntries = await _context.AuditLogEntries.ToListAsync();
        }
    }
}
