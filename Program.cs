using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// -------------------------------------------------
//  CORS — อนุญาต React (localhost:5173) และ Render 
// -------------------------------------------------
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowFrontend", policy =>
    {
        policy.WithOrigins(
            "http://localhost:5173",
            "https://budget-tracker-frontend.onrender.com"
        )
        .AllowAnyHeader()
        .AllowAnyMethod()
        .AllowCredentials();
    });
});

// -------------------------------------------------
//  Controllers
// -------------------------------------------------
builder.Services.AddControllers();

// -------------------------------------------------
//  Authentication (ถ้ามี)
// -------------------------------------------------
var jwtKey = builder.Configuration["Jwt:Key"];
var jwtIssuer = builder.Configuration["Jwt:Issuer"];

if (!string.IsNullOrEmpty(jwtKey))
{
    builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
        .AddJwtBearer(options =>
        {
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = false,
                ValidateIssuerSigningKey = true,
                ValidIssuer = jwtIssuer,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey))
            };
        });
}

var app = builder.Build();

// -------------------------------------------------
//  Middleware ลำดับสำคัญมาก! 
// -------------------------------------------------
app.UseCors("AllowFrontend");  // ต้องมาก่อน Auth + Controllers
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
