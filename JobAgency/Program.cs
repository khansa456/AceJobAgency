using JobAgency.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.DataProtection;
using JobAgency.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();
builder.Services.AddDbContext<AuthDbContext>();
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
    options.Lockout.MaxFailedAccessAttempts = 3;
    options.Lockout.AllowedForNewUsers = true;
    options.Password.RequireDigit = true;
    options.Password.RequiredLength = 12;
    options.Password.RequireLowercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequireUppercase = true;

})
.AddSignInManager<SignInManager<ApplicationUser>>()
.AddEntityFrameworkStores<AuthDbContext>()
.AddDefaultTokenProviders();

builder.Services.AddAuthorization(options =>
    options.AddPolicy("TwoFactorEnabled", x => x.RequireClaim("amr", "mfa")));

builder.Services.AddDistributedMemoryCache();

builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(20);
    options.Cookie.IsEssential = true;
    options.Cookie.HttpOnly = true;
});

builder.Services.ConfigureApplicationCookie(config =>
{
    config.LoginPath = "/login";
    config.AccessDeniedPath = "/Identity/Account/AccessDenied";
    config.SlidingExpiration = true;
    config.LoginPath = "/register";
    config.Cookie.SameSite = Microsoft.AspNetCore.Http.SameSiteMode.None;
    config.Cookie.SecurePolicy = Microsoft.AspNetCore.Http.CookieSecurePolicy.Always; // Enable this in production
});

builder.Services.AddTransient<IEmailSender, EmailSender>();

builder.Services.Configure<DataProtectionTokenProviderOptions>(o =>
{
    o.TokenLifespan = TimeSpan.FromHours(2); // Adjust this value as needed
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseStatusCodePagesWithRedirects("/Errors/{0}");
app.UseRouting();

app.UseAuthentication();  // Make sure this comes before UseAuthorization
app.UseAuthorization();
app.UseSession();

app.MapRazorPages();

app.Run();
