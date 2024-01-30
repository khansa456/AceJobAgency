using System.Net.Mail;
using System.Net;
using System.Text;

namespace JobAgency.Services
{
    public class EmailSender : IEmailSender
    {
        public void SendEmail(string toEmail, string subject, string body)
        {
            // Set up SMTP client
            SmtpClient client = new SmtpClient("smtp.gmail.com", 587);
            client.EnableSsl = true;
            client.UseDefaultCredentials = false;
            client.Credentials = new NetworkCredential("aceajency01@gmail.com", "paim gnwq fcqk fusi");


            // Create email message
            MailMessage mailMessage = new MailMessage();
            mailMessage.From = new MailAddress("khansatamba@gmail.com");
            mailMessage.To.Add(toEmail);
            mailMessage.Subject = subject;
            mailMessage.IsBodyHtml = true;
            mailMessage.Body = body;

            // Send email
            client.Send(mailMessage);
        }
    }
}
