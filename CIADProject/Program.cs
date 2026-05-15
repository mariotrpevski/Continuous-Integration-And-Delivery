using IBLabProject;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using System.Text.Json;
using System.Text.RegularExpressions;

var builder = WebApplication.CreateBuilder(args);

// Services
builder.Services.AddSingleton<EmailSender>();
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));
builder.Services.AddDistributedMemoryCache();
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/login.html";
        options.AccessDeniedPath = "/access-denied.html";
    });
builder.Services.AddAuthorization();
builder.Services.AddSession();

var app = builder.Build();
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    db.Database.Migrate();
}

// ----------------- Default page -----------------
var options = new DefaultFilesOptions();
options.DefaultFileNames.Clear();
options.DefaultFileNames.Add("login.html");
app.UseDefaultFiles(options);
app.UseStaticFiles();

// ----------------- Middleware -----------------
app.UseSession();
app.UseAuthentication();
app.UseAuthorization();

// ---------------- REGISTER ----------------
app.MapPost("/register", async (HttpContext ctx, EmailSender emailSender) =>
{
    var form = await ctx.Request.ReadFromJsonAsync<RegisterRequest>();
    if (form == null)
        return Results.BadRequest("Invalid data");

    var emailRegex = new Regex(@"^[^@\s]+@[^@\s]+\.[^@\s]+$");
    if (!emailRegex.IsMatch(form.Email))
        return Results.BadRequest("Invalid email format");

    var passwordRegex = new Regex(@"^(?=.*[A-Z])(?=.*[!@#$%^&*(),.?""{|}|<>]).{8,}$");
    if (!passwordRegex.IsMatch(form.Password))
        return Results.BadRequest("Password must be at least 8 characters, contain 1 uppercase letter and 1 symbol");

    using var scope = app.Services.CreateScope();
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();

    if (await db.Users.AnyAsync(u => u.Email == form.Email))
        return Results.BadRequest("User already exists");

    var code = Random.Shared.Next(100000, 999999).ToString();
    ctx.Session.SetString("pending_user", JsonSerializer.Serialize(form));
    ctx.Session.SetString("verification_code", code);

    await emailSender.SendVerificationCodeAsync(form.Email, form.Username, code);
    return Results.Ok("Verification code sent");
});


// ---------------- CONFIRM EMAIL ----------------
app.MapPost("/confirm", async (HttpContext ctx) =>
{
    var inputCode = ctx.Request.Form["code"].ToString();
    var storedCode = ctx.Session.GetString("verification_code");
    var pendingUserJson = ctx.Session.GetString("pending_user");

    if (storedCode != inputCode || pendingUserJson == null)
        return Results.BadRequest("Invalid code");

    var pendingUser = JsonSerializer.Deserialize<RegisterRequest>(pendingUserJson)!;

    using var scope = app.Services.CreateScope();
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();

    var role = pendingUser.Username == "MAdmin" ? "Admin" : "User";

    db.Users.Add(new User
    {
        Email = pendingUser.Email,
        Username = pendingUser.Username,
        PasswordHash = PasswordHasher.Hash(pendingUser.Password),
        Role = role,
        RequestsApproved = false
    });

    await db.SaveChangesAsync();
    ctx.Session.Clear();
    return Results.Redirect("/login.html");
});

app.MapPost("/login", async (HttpContext ctx, EmailSender emailSender) =>
{
    var form = await ctx.Request.ReadFromJsonAsync<LoginRequest>();

    using var scope = app.Services.CreateScope();
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();

    var user = await db.Users.FirstOrDefaultAsync(u => u.Email == form!.Email);
    if (user == null || !PasswordHasher.Verify(form!.Password, user.PasswordHash))
        return Results.BadRequest("Invalid credentials");

    var code = Random.Shared.Next(100000, 999999).ToString();
    ctx.Session.SetString("2fa_user", user.Email);
    ctx.Session.SetString("2fa_code", code);

    await emailSender.SendVerificationCodeAsync(user.Email, user.Username, code);

    return Results.Ok("2FA code sent");
});

// ---------------- VERIFY 2FA ----------------
app.MapPost("/verify-2fa", async (HttpContext ctx) =>
{
    var codeInput = ctx.Request.Form["code"].ToString();
    var storedCode = ctx.Session.GetString("2fa_code");
    var email = ctx.Session.GetString("2fa_user");

    if (storedCode != codeInput || email == null)
        return Results.BadRequest("Invalid code");

    using var scope = app.Services.CreateScope();
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    var user = await db.Users.FirstAsync(u => u.Email == email);
    var role = user.Role;

    var claims = new List<Claim>
    {
        new Claim(ClaimTypes.Name, user.Username),
        new Claim(ClaimTypes.Role, role)
    };

    var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
    var principal = new ClaimsPrincipal(identity);

    await ctx.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

    ctx.Session.Remove("2fa_code");
    ctx.Session.Remove("2fa_user");

    return Results.Redirect("/welcome.html");
});

// ---------------- LOGOUT ----------------
app.MapPost("/logout", async (HttpContext ctx) =>
{
    await ctx.SignOutAsync();
    return Results.Ok("Logged out");
});

// ---------------- CURRENT USER ----------------
app.MapGet("/me", [Authorize] (ClaimsPrincipal user) =>
{
    return Results.Ok(new
    {
        Username = user.Identity!.Name,
        Role = user.FindFirst(ClaimTypes.Role)?.Value
    });
});

// ---------------- ADMIN DASHBOARD ----------------
app.MapGet("/admin/dashboard", async () =>
{
    using var scope = app.Services.CreateScope();
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();

    var regularUsers = await db.Users
        .Where(u => u.Role != "Admin")
        .ToListAsync();

    return Results.Ok(regularUsers);
}).RequireAuthorization(new AuthorizeAttribute { Roles = "Admin" });


// ---------------- USER REQUEST ----------------
app.MapPost("/user/request-info", async (HttpContext ctx) =>
{
    var username = ctx.User.Identity!.Name;

    using var scope = app.Services.CreateScope();
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    var user = await db.Users.FirstAsync(u => u.Username == username);

    user.RequestsApproved = false;
    user.ApprovalTime = null;
    await db.SaveChangesAsync();

    return Results.Ok("Request sent");
}).RequireAuthorization();

// ---------------- ADMIN APPROVE/DENY ----------------
app.MapPost("/admin/approve/{username}", async (string username) =>
{
    using var scope = app.Services.CreateScope();
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    var user = await db.Users.FirstAsync(u => u.Username == username);

    user.RequestsApproved = true;
    user.ApprovalTime = DateTime.UtcNow;
    await db.SaveChangesAsync();

    return Results.Ok("Approved");
}).RequireAuthorization(new AuthorizeAttribute { Roles = "Admin" });

app.MapPost("/admin/deny/{username}", async (string username) =>
{
    using var scope = app.Services.CreateScope();
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    var user = await db.Users.FirstAsync(u => u.Username == username);

    user.RequestsApproved = false;
    user.ApprovalTime = null;
    await db.SaveChangesAsync();

    return Results.Ok("Denied");
}).RequireAuthorization(new AuthorizeAttribute { Roles = "Admin" });


// ---------------- DOWNLOAD INFO ----------------
app.MapGet("/user/download-info", async (HttpContext ctx) =>
{
    var username = ctx.User.Identity!.Name;

    using var scope = app.Services.CreateScope();
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    var user = await db.Users.FirstAsync(u => u.Username == username);

    if (user.Role != "Admin" && !user.RequestsApproved)
        return Results.BadRequest("Not approved");

    var content = $"Username: {user.Username}\nEmail: {user.Email}\nRole: {user.Role}";
    return Results.File(
        System.Text.Encoding.UTF8.GetBytes(content),
        "text/plain",
        "userinfo.txt");
}).RequireAuthorization();

// Check request status for current user
app.MapGet("/user/request-status", async (HttpContext ctx) =>
{
    var username = ctx.User.Identity!.Name;

    using var scope = app.Services.CreateScope();
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    var user = await db.Users.FirstAsync(u => u.Username == username);

    if (user.RequestsApproved && user.ApprovalTime.HasValue)
    {
        var elapsed = DateTime.UtcNow - user.ApprovalTime.Value;
        var remaining = TimeSpan.FromMinutes(10) - elapsed;

        if (remaining.TotalSeconds <= 0)
        {
            user.RequestsApproved = false;
            user.ApprovalTime = null;
            await db.SaveChangesAsync();
            return Results.Json(new { status = "Denied", remainingSeconds = 0 });
        }

        return Results.Json(new { status = "Approved", remainingSeconds = (int)Math.Ceiling(remaining.TotalSeconds) });
    }

    return Results.Json(new { status = "Denied", remainingSeconds = 0 });
}).RequireAuthorization();


app.Run();


// ---------------- MODELS ----------------

public class User
{
    public int Id { get; set; }
    public string Email { get; set; } = "";
    public string Username { get; set; } = "";
    public string PasswordHash { get; set; } = "";
    public string Role { get; set; } = "User";
    public bool RequestsApproved { get; set; }
    public DateTime? ApprovalTime { get; set; }
}

public class RegisterRequest
{
    public string Email { get; set; } = "";
    public string Username { get; set; } = "";
    public string Password { get; set; } = "";
}

public class LoginRequest
{
    public string Email { get; set; } = "";
    public string Password { get; set; } = "";
}