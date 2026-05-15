using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;

public class EmailSender
{
    private readonly IConfiguration _cfg;
    public EmailSender(IConfiguration cfg) => _cfg = cfg;

    public async Task SendVerificationCodeAsync(string toEmail, string username, string code)
    {
        var message = new MimeMessage();
        message.From.Add(MailboxAddress.Parse(_cfg["Smtp:From"] ?? "noreply@example.com"));
        message.To.Add(MailboxAddress.Parse(toEmail));
        message.Subject = "Your verification code";
        message.Body = new TextPart("plain")
        {
            Text = $"Hello {username},\n\nYour verification code is: {code}\nIt expires in 15 minutes.\n\nIf you didn't request this, ignore this email."
        };

        using var client = new SmtpClient();
        // Use the SMTP configuration from appsettings or env variables
        var host = _cfg["Smtp:Host"] ?? throw new InvalidOperationException("Smtp:Host not configured");
        var port = int.Parse(_cfg["Smtp:Port"] ?? "587");
        var user = _cfg["Smtp:User"] ?? string.Empty;
        var pass = _cfg["Smtp:Pass"] ?? string.Empty;
        var useSslConfigured = bool.TryParse(_cfg["Smtp:UseSsl"], out var useSsl) && useSsl;

        SecureSocketOptions secureOptions;
        if (port == 465)
        {
            secureOptions = SecureSocketOptions.SslOnConnect;
        }
        else if (port == 587)
        {
            secureOptions = SecureSocketOptions.StartTls;
        }
        else
        {
            secureOptions = useSslConfigured ? SecureSocketOptions.SslOnConnect : SecureSocketOptions.Auto;
        }

        await client.ConnectAsync(host, port, secureOptions);
        if (!string.IsNullOrEmpty(user))
            await client.AuthenticateAsync(user, pass);
        await client.SendAsync(message);
        await client.DisconnectAsync(true);
    }
}