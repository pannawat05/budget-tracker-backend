using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// -------------------------------------------------
// 1) CORS — แก้ปัญหา React (5173) เรียกไม่ได้ / Render 500
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
// 2) Controllers (ทำให้ endpoint เดิมทั้งหมดยังทำงาน)
// -------------------------------------------------
builder.Services.AddControllers();

// -------------------------------------------------
// 3) Authentication (ถ้าโปรเจกต์มี JWT)
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

// -------------------------------------------------
// Build app
// -------------------------------------------------
var app = builder.Build();

// -------------------------------------------------
// 4) Middlewares — ลำดับสำคัญมาก (แก้ 500 CORS กรณีคุณเจอ)
// -------------------------------------------------
app.UseCors("AllowFrontend");   // ต้องมาก่อน Authentication + Controllers
app.UseAuthentication();
app.UseAuthorization();

// -------------------------------------------------
// 5) Endpoint เดิมทั้งหมดจะทำงานจากไฟล์ Controller
// -------------------------------------------------
app.MapControllers();  

// -------------------------------------------------
app.Run();
