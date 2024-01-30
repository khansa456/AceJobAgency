using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Linq;
using System.Security.Claims;

namespace JobAgency.Model
{
    public class AuthorizeSessionAttribute : Attribute, IPageFilter
    {
        public void OnPageHandlerExecuting(PageHandlerExecutingContext context)
        {
            var dbContext = context.HttpContext.RequestServices.GetRequiredService<AuthDbContext>();

            var userId = context.HttpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);

            if (string.IsNullOrEmpty(userId))
            {
                context.Result = new RedirectToPageResult("/Login");
                return;
            }

            var sessionId = context.HttpContext.Session.Id;

            var activeSession = dbContext.UserSessions
                .Where(s => s.UserId == userId && s.SessionId == sessionId && s.ExpirationTime > DateTime.Now)
                .OrderByDescending(s => s.CreatedAt)
                .FirstOrDefault();

        }

        public void OnPageHandlerExecuted(PageHandlerExecutedContext context) { }
        public void OnPageHandlerSelected(PageHandlerSelectedContext context) { }
    }
}
