using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.EntityFrameworkCore;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration; // เพิ่ม Using นี้เผื่อ Environment Variables

// ================= CONFIG =================
var builder = WebApplication.CreateBuilder(args);

// Read from Environment Variables (Render + local)
var dbHost = Environment.GetEnvironmentVariable("Server") ?? "localhost";
var dbPort = Environment.GetEnvironmentVariable("Port") ?? "5432";
var dbUser = Environment.GetEnvironmentVariable("Id") ?? "postgres";
var dbPass = Environment.GetEnvironmentVariable("Password") ?? "";
var dbName = Environment.GetEnvironmentVariable("Database") ?? "postgres";

var jwtKey = Environment.GetEnvironmentVariable("JWT_KEY") ?? "ThisIsMyUltraSecureJwtKey_AtLeast32CharsLong!!";
var jwtIssuer = Environment.GetEnvironmentVariable("JWT_ISSUER") ?? "MyAppIssuer";

var connectionString = $"Host={dbHost};Port={dbPort};Username={dbUser};Password={dbPass};Database={dbName};Ssl Mode=Require;Trust Server Certificate=True;";

Console.WriteLine($"🔗 Using database: {connectionString.Replace(dbPass, "***")}");

// ================= SERVICES =================
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = false,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtIssuer,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey))
        };
    });

builder.Services.AddAuthorization();

// CORS - allow everything (Render + Local)
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyHeader()
              .AllowAnyMethod();
    });
});

builder.Services.AddDbContext<MyDbContext>(options =>
    options.UseNpgsql(connectionString));

builder.Services.AddMemoryCache();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// เพิ่มบรรทัดนี้เพื่อเปิดใช้งาน Routing
builder.Services.AddRouting();

var app = builder.Build();

// ================= MIDDLEWARE =================
// 1. Swagger (ควรอยู่บนสุดสำหรับ Development)
app.UseSwagger();
app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("/swagger/v1/swagger.json", "Budget Tracker API v1");
    c.RoutePrefix = string.Empty;
});

// 2. เพิ่ม UseRouting()
// ทำให้ Middleware ที่มาทีหลัง (เช่น Cors, Auth) รู้ว่ากำลังจะเรียก Endpoint ไหน
app.UseRouting();

// 3. ย้าย UseCors() มาไว้หลัง UseRouting() และก่อน Auth
app.UseCors();

// 4. Auth Middleware
app.UseAuthentication();
app.UseAuthorization();

// 5. ย้าย Token blacklist middleware มาไว้หลัง Auth ทั้งหมด
//    และเปลี่ยนมาเช็คจาก context.User ที่ผ่านการ Validate แล้ว
app.Use(async (context, next) =>
{
    // ตรวจสอบว่า User ผ่านการยืนยันตัวตนมาแล้วหรือยัง
    if (context.User.Identity?.IsAuthenticated == true)
    {
        var cache = context.RequestServices.GetRequiredService<IMemoryCache>();
        
        // ดึง jti จาก Claims ที่ผ่านการ Validate แล้ว (ไม่ต้อง Parse Token เอง)
        var jti = context.User.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Jti)?.Value;

        if (!string.IsNullOrEmpty(jti) && cache.TryGetValue($"blacklist_{jti}", out _))
        {
            // ถ้า Token อยู่ใน Blacklist ให้ส่ง 401
            context.Response.StatusCode = 401;
            await context.Response.WriteAsJsonAsync(new { error = "Token has been revoked" });
            return;
        }
    }

    // ถ้าไม่ติด Blacklist (หรือไม่ได้ Login) ก็ไปต่อ
    await next();
});


// ================= ENDPOINTS =================
// (Endpoints ทั้งหมดของคุณจะถูก Map โดยอัตโนมัติ)

// Health check
app.MapGet("/health", () => Results.Ok(new
{
    status = "healthy",
    timestamp = DateTime.UtcNow,
    environment = app.Environment.EnvironmentName
}));

// -------- REGISTER --------
app.MapPost("/register", async (MyDbContext db, User user) =>
{
    if (await db.Users.AnyAsync(u => u.Email == user.Email))
        return Results.BadRequest("Email already registered");

    user.Id = Guid.NewGuid();
    user.CreatedAt = DateTime.UtcNow;
    user.Password = BCrypt.Net.BCrypt.HashPassword(user.Password);

    db.Users.Add(user);
    await db.SaveChangesAsync();

    return Results.Ok(new { message = "User registered successfully" });
});

// -------- LOGIN --------
app.MapPost("/login", async (MyDbContext db, LoginRequest req) =>
{
    var user = await db.Users.FirstOrDefaultAsync(u => u.Email == req.Email);
    if (user == null || !BCrypt.Net.BCrypt.Verify(req.Password, user.Password))
        return Results.Unauthorized();

    var handler = new JwtSecurityTokenHandler();
    var keyBytes = Encoding.UTF8.GetBytes(jwtKey);

    var tokenDescriptor = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(new[]
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Email, user.Email),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()) // JTI สำหรับ Blacklist
        }),
        Expires = DateTime.UtcNow.AddHours(2),
        Issuer = jwtIssuer,
        SigningCredentials = new SigningCredentials(
            new SymmetricSecurityKey(keyBytes),
            SecurityAlgorithms.HmacSha256Signature)
    };

    var token = handler.CreateToken(tokenDescriptor);
    var jwt = handler.WriteToken(token);

    return Results.Ok(new { token = jwt });
});

// -------- LOGOUT --------
// [Authorize] ทำงานร่วมกับ Blacklist Middleware ที่เราย้ายไป
app.MapPost("/logout", [Authorize] async (ClaimsPrincipal user, IMemoryCache cache) =>
{
    // ไม่ต้อง Parse Token เองแล้ว ดึงจาก ClaimsPrincipal (user) ได้เลย
    var jti = user.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Jti)?.Value;
    if (string.IsNullOrEmpty(jti)) 
        return Results.BadRequest(new { error = "Invalid token (missing jti)" });

    // ดึง Expiry จาก Token
    var expiryClaim = user.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Exp)?.Value;
    if (!long.TryParse(expiryClaim, out var expiryUnix))
        return Results.BadRequest(new { error = "Invalid token (missing exp)" });

    var expiry = DateTimeOffset.FromUnixTimeSeconds(expiryUnix).UtcDateTime;
    if (expiry <= DateTime.UtcNow) 
        return Results.BadRequest(new { error = "Token already expired" });
    
    // เพิ่มเข้า Blacklist ตามเวลาที่เหลือของ Token
    cache.Set($"blacklist_{jti}", true, expiry - DateTime.UtcNow);

    return Results.Ok(new { message = "Logged out successfully" });
});

// -------- PROFILE --------
app.MapGet("/profile", [Authorize] async (ClaimsPrincipal user, MyDbContext db) =>
{
    var idStr = user.FindFirstValue(ClaimTypes.NameIdentifier);
    if (!Guid.TryParse(idStr, out var userId))
        return Results.Problem("Invalid user ID", statusCode: 401);

    var profile = await db.Users.FindAsync(userId);
    if (profile == null)
        return Results.NotFound(new { error = "User not found" });

    return Results.Ok(new
    {
        id = profile.Id,
        email = profile.Email,
        createdAt = profile.CreatedAt
    });
});

// -------- CATEGORIES --------
app.MapGet("/categories", [Authorize] async (ClaimsPrincipal user, MyDbContext db) =>
{
    var idStr = user.FindFirstValue(ClaimTypes.NameIdentifier);
    if (!Guid.TryParse(idStr, out var userId))
        return Results.Problem("Invalid user ID", statusCode: 401);

    var categories = await db.Categories
        .Where(c => c.UserId == userId)
        .OrderBy(c => c.Name)
        .Select(c => new { c.Id, c.Name, c.Type, c.Icon, c.Color })
        .ToListAsync();

    return Results.Ok(categories);
});

app.MapPost("/categories", [Authorize] async (ClaimsPrincipal user, MyDbContext db, CategoryRequest req) =>
{
    var idStr = user.FindFirstValue(ClaimTypes.NameIdentifier);
    if (!Guid.TryParse(idStr, out var userId))
        return Results.Problem("Invalid user ID", statusCode: 401);

    var category = new Category
    {
        Id = Guid.NewGuid(),
        UserId = userId,
        Name = req.Name,
        Type = req.Type,
        Icon = req.Icon,
        Color = req.Color,
        CreatedAt = DateTime.UtcNow
    };

    db.Categories.Add(category);
    await db.SaveChangesAsync();

    return Results.Ok(new { message = "Category created successfully" });
});

// -------- BUDGETS --------
app.MapGet("/budgets", [Authorize] async (ClaimsPrincipal user, MyDbContext db) =>
{
    var idStr = user.FindFirstValue(ClaimTypes.NameIdentifier);
    if (!Guid.TryParse(idStr, out var userId))
        return Results.Problem("Invalid user ID", statusCode: 401);

    var budgets = await db.Budgets
        .Where(b => b.UserId == userId)
        .OrderByDescending(b => b.Year)
        .ThenByDescending(b => b.Month)
        .ToListAsync();

    return Results.Ok(budgets);
});

app.MapPost("/budgets", [Authorize] async (ClaimsPrincipal user, MyDbContext db, BudgetRequest req) =>
{
    var idStr = user.FindFirstValue(ClaimTypes.NameIdentifier);
    if (!Guid.TryParse(idStr, out var userId))
        return Results.Problem("Invalid user ID", statusCode: 401);

    var category = await db.Categories.FindAsync(req.CategoryId);
    if (category == null || category.UserId != userId)
        return Results.BadRequest("Invalid category");

    var budget = new Budget
    {
        Id = Guid.NewGuid(),
        UserId = userId,
        CategoryId = req.CategoryId,
        Month = req.Month,
        Year = req.Year,
        LimitAmount = req.LimitAmount,
        CreatedAt = DateTime.UtcNow
    };

    db.Budgets.Add(budget);
    await db.SaveChangesAsync();

    return Results.Ok(new { message = "Budget created successfully", budget });
});

// -------- TRANSACTIONS --------
app.MapPost("/add-transaction", [Authorize] async (ClaimsPrincipal user, MyDbContext db, TransactionRequest req) =>
{
    var idStr = user.FindFirstValue(ClaimTypes.NameIdentifier);
    if (!Guid.TryParse(idStr, out var userId))
        return Results.Problem("Invalid user ID", statusCode: 401);

    if (!Guid.TryParse(req.CategoryId, out var categoryId))
        return Results.BadRequest("Invalid category ID");

    var category = await db.Categories.FindAsync(categoryId);
    if (category == null || category.UserId != userId)
        return Results.BadRequest("Invalid category");

    var transaction = new Transaction
    {
        Id = Guid.NewGuid(),
        UserId = userId,
        CategoryId = categoryId,
        Amount = req.Amount,
        Type = req.Type,
        Note = req.Note ?? "",
        CreatedAt = DateTime.UtcNow
    };

    db.Transactions.Add(transaction);
    await db.SaveChangesAsync();

    return Results.Ok(new { message = "Transaction added", transaction });
});

app.MapGet("/transactions", [Authorize] async (ClaimsPrincipal user, MyDbContext db) =>
{
    var idStr = user.FindFirstValue(ClaimTypes.NameIdentifier);
    if (!Guid.TryParse(idStr, out var userId))
        return Results.Problem("Invalid user ID", statusCode: 401);

    var list = await db.Transactions
        .Where(t => t.UserId == userId)
        .Join(db.Categories,
            t => t.CategoryId,
            c => c.Id,
            (t, c) => new
            {
                t.Id,
                t.Amount,
                t.Type,
                t.Note,
                t.CreatedAt,
                CategoryName = c.Name
            })
        .OrderByDescending(t => t.CreatedAt)
        .ToListAsync();

    return Results.Ok(list);
});

Console.WriteLine("✅ Application configured successfully");
app.Run();


// ================= MODELS =================
public class LoginRequest { public string Email { get; set; } = null!; public string Password { get; set; } = null!; }
public class User { public Guid Id { get; set; } public string Email { get; set; } = null!; public string Password { get; set; } = null!; public DateTime CreatedAt { get; set; } }
public class Category { public Guid Id { get; set; } public Guid UserId { get; set; } public string Name { get; set; } = null!; public string Type { get; set; } = null!; public string? Icon { get; set; } public string? Color { get; set; } public DateTime CreatedAt { get; set; } }
public class CategoryRequest { public string Name { get; set; } = null!; public string Type { get; set; } = null!; public string? Icon { get; set; } public string? Color { get; set; } }
public class Budget { public Guid Id { get; set; } public Guid UserId { get; set; } public Guid CategoryId { get; set; } public int Month { get; set; } public int Year { get; set; } public decimal LimitAmount { get; set; } public DateTime CreatedAt { get; set; } }
public class BudgetRequest { public Guid CategoryId { get; set; } public int Month { get; set; } public int Year { get; set; } public decimal LimitAmount { get; set; } }
public class TransactionRequest { public string CategoryId { get; set; } = null!; public decimal Amount { get; set; } public string Type { get; set; } = null!; public string? Note { get; set; } }
public class Transaction { public Guid Id { get; set; } public Guid UserId { get; set; } public Guid CategoryId { get; set; } public decimal Amount { get; set; } public string Type { get; set; } = null!; public string Note { get; set; } = ""; public DateTime CreatedAt { get; set; } }

// ================= DB CONTEXT =================
public class MyDbContext : DbContext
{
    public MyDbContext(DbContextOptions<MyDbContext> options) : base(options) { }

    public DbSet<User> Users => Set<User>();
    public DbSet<Category> Categories => Set<Category>();
    public DbSet<Budget> Budgets => Set<Budget>();
    public DbSet<Transaction> Transactions => Set<Transaction>();

    protected override void OnModelCreating(ModelBuilder model)
    {
        base.OnModelCreating(model);

        model.Entity<User>().ToTable("users");
        model.Entity<Category>().ToTable("categories");
        model.Entity<Budget>().ToTable("budgets");
        model.Entity<Transaction>().ToTable("transactions");
    }
}
