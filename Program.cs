using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.EntityFrameworkCore;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.AspNetCore.Authorization;

// ================= CONFIG =================
var builder = WebApplication.CreateBuilder(args);

// Read from Environment Variables (works for both local .env and Render)
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
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),
            ClockSkew = TimeSpan.FromMinutes(5), // เพิ่ม clock skew tolerance
            NameClaimType = ClaimTypes.NameIdentifier // กำหนด name claim type
        };

        // เพิ่ม event เพื่อ debug
        options.Events = new JwtBearerEvents
        {
            OnAuthenticationFailed = context =>
            {
                Console.WriteLine($"❌ JWT Authentication Failed: {context.Exception.Message}");
                if (context.Exception.InnerException != null)
                {
                    Console.WriteLine($"   Inner: {context.Exception.InnerException.Message}");
                }
                return Task.CompletedTask;
            },
            OnTokenValidated = context =>
            {
                var userId = context.Principal?.FindFirstValue(ClaimTypes.NameIdentifier);
                Console.WriteLine($"✅ JWT Token Validated. UserId: {userId}");
                
                // Debug all claims
                if (context.Principal != null)
                {
                    foreach (var claim in context.Principal.Claims)
                    {
                        Console.WriteLine($"   Claim: {claim.Type} = {claim.Value}");
                    }
                }
                
                return Task.CompletedTask;
            },
            OnChallenge = context =>
            {
                Console.WriteLine($"⚠️ JWT Challenge: {context.Error}, {context.ErrorDescription}");
                Console.WriteLine($"   AuthenticateFailure: {context.AuthenticateFailure?.Message}");
                return Task.CompletedTask;
            },
            OnMessageReceived = context =>
            {
                var authHeader = context.Request.Headers["Authorization"].ToString();
                Console.WriteLine($"📨 Message Received. Auth header: {(string.IsNullOrEmpty(authHeader) ? "MISSING" : "Present")}");
                return Task.CompletedTask;
            }
        };
    });

builder.Services.AddAuthorization();

// CORS - เพิ่ม policy ชื่อเฉพาะ
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", policy =>
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

var app = builder.Build();

// ================= MIDDLEWARE =================
app.UseSwagger();
app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("/swagger/v1/swagger.json", "Budget Tracker API v1");
    c.RoutePrefix = string.Empty;
});

// ⚠️ CRITICAL: CORS ต้องมาก่อน Authentication/Authorization
app.UseCors("AllowAll");

// Global Exception Handler เพื่อให้ CORS headers ถูกส่งไปแม้เกิด error
app.Use(async (context, next) =>
{
    try
    {
        await next();
    }
    catch (Exception ex)
    {
        Console.WriteLine($"❌ Unhandled exception: {ex.Message}");
        context.Response.StatusCode = 500;
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsJsonAsync(new { error = "Internal server error", details = ex.Message });
    }
});

app.Use(async (context, next) =>
{
    var cache = context.RequestServices.GetRequiredService<IMemoryCache>();
    var authHeader = context.Request.Headers["Authorization"].ToString();

    // Debug logging
    Console.WriteLine($"🔍 Path: {context.Request.Path}");
    Console.WriteLine($"🔍 Auth Header: {(string.IsNullOrEmpty(authHeader) ? "MISSING" : "Present")}");

    if (!string.IsNullOrEmpty(authHeader) && authHeader.StartsWith("Bearer "))
    {
        var token = authHeader.Substring(7);
        try
        {
            var handler = new JwtSecurityTokenHandler();
            var jwt = handler.ReadJwtToken(token);
            var jti = jwt.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Jti)?.Value;

            if (!string.IsNullOrEmpty(jti) && cache.TryGetValue($"blacklist_{jti}", out _))
            {
                Console.WriteLine($"⛔ Token blacklisted: {jti}");
                context.Response.StatusCode = 401;
                await context.Response.WriteAsJsonAsync(new { error = "Token has been revoked" });
                return;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"⚠️ Token validation error: {ex.Message}");
        }
    }

    await next();
});

app.UseAuthentication();
app.UseAuthorization();

// ================= ENDPOINTS =================

// Health check
app.MapGet("/health", () => Results.Ok(new 
{ 
    status = "healthy",
    timestamp = DateTime.UtcNow,
    environment = app.Environment.EnvironmentName
}));

// Debug endpoint to test token
app.MapGet("/debug/token", async (HttpContext context) =>
{
    var authHeader = context.Request.Headers["Authorization"].ToString();
    
    if (string.IsNullOrEmpty(authHeader))
        return Results.Ok(new { error = "No Authorization header" });
    
    if (!authHeader.StartsWith("Bearer "))
        return Results.Ok(new { error = "Invalid Authorization format" });
    
    var token = authHeader.Substring(7);
    
    try
    {
        var handler = new JwtSecurityTokenHandler();
        var jwt = handler.ReadJwtToken(token);
        
        var claims = jwt.Claims.Select(c => new { c.Type, c.Value }).ToList();
        
        return Results.Ok(new 
        { 
            valid = true,
            issuer = jwt.Issuer,
            expires = jwt.ValidTo,
            isExpired = jwt.ValidTo < DateTime.UtcNow,
            claims = claims
        });
    }
    catch (Exception ex)
    {
        return Results.Ok(new { error = $"Token parse failed: {ex.Message}" });
    }
});

// Test authenticated endpoint
app.MapGet("/debug/auth", [Authorize] (HttpContext context) =>
{
    var user = context.User;
    var userId = user.FindFirstValue(ClaimTypes.NameIdentifier);
    var email = user.FindFirstValue(ClaimTypes.Email);
    
    return Results.Ok(new
    {
        authenticated = user.Identity?.IsAuthenticated ?? false,
        userId = userId,
        email = email,
        claims = user.Claims.Select(c => new { c.Type, c.Value }).ToList()
    });
}).RequireAuthorization();

// -------- REGISTER --------
app.MapPost("/register", async (MyDbContext db, User user) =>
{
    try
    {
        if (await db.Users.AnyAsync(u => u.Email == user.Email))
            return Results.BadRequest("Email already registered");

        user.Id = Guid.NewGuid();
        user.CreatedAt = DateTime.UtcNow;
        user.Password = BCrypt.Net.BCrypt.HashPassword(user.Password);

        db.Users.Add(user);
        await db.SaveChangesAsync();

        return Results.Ok(new { message = "User registered successfully" });
    }
    catch (Exception ex)
    {
        Console.WriteLine($"❌ Register error: {ex.Message}");
        return Results.Problem($"Registration failed: {ex.Message}", statusCode: 500);
    }
});

// -------- LOGIN --------
app.MapPost("/login", async (MyDbContext db, LoginRequest req) =>
{
    try
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
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
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
    }
    catch (Exception ex)
    {
        Console.WriteLine($"❌ Login error: {ex.Message}");
        return Results.Problem($"Login failed: {ex.Message}", statusCode: 500);
    }
});

// -------- LOGOUT --------
app.MapPost("/logout", [Authorize] async (HttpContext context, IMemoryCache cache) =>
{
    try
    {
        var authHeader = context.Request.Headers["Authorization"].ToString();
        if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
            return Results.BadRequest(new { error = "No token provided" });

        var token = authHeader.Substring(7);
        var handler = new JwtSecurityTokenHandler();
        var jwt = handler.ReadJwtToken(token);
        var jti = jwt.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Jti)?.Value;
        if (string.IsNullOrEmpty(jti)) return Results.BadRequest(new { error = "Invalid token" });

        var expiry = jwt.ValidTo;
        if (expiry <= DateTime.UtcNow) return Results.BadRequest(new { error = "Token already expired" });

        cache.Set($"blacklist_{jti}", true, expiry - DateTime.UtcNow);

        return Results.Ok(new { message = "Logged out successfully" });
    }
    catch (Exception ex)
    {
        Console.WriteLine($"❌ Logout error: {ex.Message}");
        return Results.Problem($"Error during logout: {ex.Message}", statusCode: 500);
    }
}).RequireAuthorization();

// -------- PROFILE --------
app.MapGet("/profile", [Authorize] async (ClaimsPrincipal user, MyDbContext db) =>
{
    try
    {
        var idStr = user.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!Guid.TryParse(idStr, out var userId)) return Results.Problem("Invalid user ID", statusCode: 401);

        var profile = await db.Users.FindAsync(userId);
        if (profile == null) return Results.NotFound();

        return Results.Ok(new { profile.Id, profile.Email, profile.CreatedAt });
    }
    catch (Exception ex)
    {
        Console.WriteLine($"❌ Profile error: {ex.Message}");
        return Results.Problem($"Error fetching profile: {ex.Message}", statusCode: 500);
    }
}).RequireAuthorization();

// -------- CATEGORIES --------
app.MapGet("/categories", [Authorize] async (ClaimsPrincipal user, MyDbContext db) =>
{
    try
    {
        var idStr = user.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!Guid.TryParse(idStr, out var userId)) return Results.Problem("Invalid user ID", statusCode: 401);

        var categories = await db.Categories
            .Where(c => c.UserId == userId)
            .OrderBy(c => c.Name)
            .Select(c => new
            {
                c.Id,
                c.Name,
                Type = c.Type ?? "",
                Icon = c.Icon ?? "",
                Color = c.Color ?? ""
            })
            .ToListAsync();

        return Results.Ok(categories);
    }
    catch (Exception ex)
    {
        Console.WriteLine($"❌ Categories error: {ex.Message}");
        return Results.Problem($"Error fetching categories: {ex.Message}", statusCode: 500);
    }
}).RequireAuthorization();

app.MapPost("/categories", [Authorize] async (ClaimsPrincipal user, MyDbContext db, CategoryRequest req) =>
{
    try
    {
        var idStr = user.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!Guid.TryParse(idStr, out var userId)) return Results.Problem("Invalid user ID", statusCode: 401);

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

        return Results.Ok(new { message = "Category created successfully", category = new { category.Id, category.Name } });
    }
    catch (Exception ex)
    {
        Console.WriteLine($"❌ Create category error: {ex.Message}");
        return Results.Problem($"Error creating category: {ex.Message}", statusCode: 500);
    }
}).RequireAuthorization();

// -------- TRANSACTIONS --------
app.MapPost("/add-transaction", async (HttpContext context, MyDbContext db, TransactionRequest req) =>
{
    try
    {
        // ตรวจสอบ Authorization header
        var authHeader = context.Request.Headers["Authorization"].ToString();
        Console.WriteLine($"🔐 Authorization Header: {(string.IsNullOrEmpty(authHeader) ? "MISSING" : "Present")}");
        
        if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
        {
            Console.WriteLine($"❌ No valid authorization header");
            return Results.Json(new { error = "Unauthorized: No token provided" }, statusCode: 401);
        }

        // ดึง user จาก HttpContext
        var user = context.User;
        
        // Debug logging
        Console.WriteLine($"🔍 User authenticated: {user.Identity?.IsAuthenticated}");
        Console.WriteLine($"🔍 User identity name: {user.Identity?.Name}");
        Console.WriteLine($"🔍 Claims count: {user.Claims.Count()}");
        
        foreach (var claim in user.Claims)
        {
            Console.WriteLine($"   - {claim.Type}: {claim.Value}");
        }

        var idStr = user.FindFirstValue(ClaimTypes.NameIdentifier);
        Console.WriteLine($"🔍 UserId from claim (NameIdentifier): {idStr}");
        
        // ลอง claim types อื่น
        if (string.IsNullOrEmpty(idStr))
        {
            idStr = user.FindFirstValue("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier");
            Console.WriteLine($"🔍 UserId from full claim type: {idStr}");
        }
        
        if (string.IsNullOrEmpty(idStr))
        {
            Console.WriteLine($"❌ Cannot find user ID in claims");
            return Results.Json(
                new { 
                    error = "Invalid user ID", 
                    authenticated = user.Identity?.IsAuthenticated,
                    claims = user.Claims.Select(c => new { c.Type, c.Value }).ToList()
                },
                statusCode: 401
            );
        }
        
        if (!Guid.TryParse(idStr, out var userId))
        {
            Console.WriteLine($"❌ Invalid GUID format: {idStr}");
            return Results.Json(
                new { error = $"Invalid user ID format: {idStr}" },
                statusCode: 401
            );
        }

        Console.WriteLine($"✅ Valid UserId: {userId}");

        if (string.IsNullOrEmpty(req.CategoryId) || !Guid.TryParse(req.CategoryId, out var categoryId))
        {
            Console.WriteLine($"❌ Invalid category ID: {req.CategoryId}");
            return Results.BadRequest(new { error = "Invalid category ID" });
        }

        var category = await db.Categories.FindAsync(categoryId);
        if (category == null)
        {
            Console.WriteLine($"❌ Category not found: {categoryId}");
            return Results.BadRequest(new { error = "Category not found" });
        }
        
        if (category.UserId != userId)
        {
            Console.WriteLine($"❌ Category belongs to different user. Category.UserId: {category.UserId}, Current UserId: {userId}");
            return Results.BadRequest(new { error = "Invalid category - not owned by user" });
        }

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

        Console.WriteLine($"💾 Saving transaction: UserId={transaction.UserId}, CategoryId={transaction.CategoryId}, Amount={transaction.Amount}");

        db.Transactions.Add(transaction);
        await db.SaveChangesAsync();

        var response = new
        {
            id = transaction.Id.ToString(),
            amount = transaction.Amount,
            type = transaction.Type ?? "",
            note = transaction.Note ?? "",
            createdAt = transaction.CreatedAt.ToString("o"),
            categoryName = category.Name
        };

        Console.WriteLine($"✅ Transaction saved successfully");
        return Results.Ok(new { message = "Transaction added successfully", transaction = response });
    }
    catch (Exception ex)
    {
        Console.WriteLine($"❌ Add transaction error: {ex.Message}");
        Console.WriteLine($"Stack trace: {ex.StackTrace}");
        return Results.Problem($"Error adding transaction: {ex.Message}", statusCode: 500);
    }
});

app.MapGet("/transactions", [Authorize] async (ClaimsPrincipal user, MyDbContext db) =>
{
    try
    {
        var idStr = user.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!Guid.TryParse(idStr, out var userId)) return Results.Problem("Invalid user ID", statusCode: 401);

        var rawTransactions = await db.Transactions
            .Where(t => t.UserId == userId)
            .Join(db.Categories,
                t => t.CategoryId,
                c => c.Id,
                (t, c) => new
                {
                    t.Id,
                    t.Amount,
                    Type = t.Type ?? "",
                    Note = t.Note ?? "",
                    t.CreatedAt,
                    CategoryName = c.Name
                })
            .OrderByDescending(t => t.CreatedAt)
            .ToListAsync();

        return Results.Ok(rawTransactions);
    }
    catch (Exception ex)
    {
        Console.WriteLine($"❌ Get transactions error: {ex.Message}");
        return Results.Problem($"Error fetching transactions: {ex.Message}", statusCode: 500);
    }
}).RequireAuthorization();

Console.WriteLine("✅ Application configured successfully");
app.Run();

// ================= MODELS =================
public class LoginRequest
{
    public string Email { get; set; } = null!;
    public string Password { get; set; } = null!;
}

public class User
{
    public Guid Id { get; set; }
    public string Email { get; set; } = null!;
    public string Password { get; set; } = null!;
    public DateTime CreatedAt { get; set; }
}

public class Category
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public string Name { get; set; } = null!;
    public string? Type { get; set; }
    public string? Icon { get; set; }
    public string? Color { get; set; }
    public DateTime CreatedAt { get; set; }
}

public class CategoryRequest
{
    public string Name { get; set; } = null!;
    public string? Type { get; set; }
    public string? Icon { get; set; }
    public string? Color { get; set; }
}

public class Transaction
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public Guid CategoryId { get; set; }
    public decimal Amount { get; set; }
    public string? Type { get; set; }
    public string? Note { get; set; }
    public DateTime CreatedAt { get; set; }
}

public class TransactionRequest
{
    public string CategoryId { get; set; } = null!;
    public decimal Amount { get; set; }
    public string? Type { get; set; }
    public string? Note { get; set; }
}

// ================= DB CONTEXT =================
public class MyDbContext : DbContext
{
    public MyDbContext(DbContextOptions<MyDbContext> options) : base(options) { }

    public DbSet<User> Users { get; set; } = null!;
    public DbSet<Category> Categories { get; set; } = null!;
    public DbSet<Transaction> Transactions { get; set; } = null!;

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<User>(entity =>
        {
            entity.ToTable("users");
            entity.Property(e => e.Id).HasColumnName("id");
            entity.Property(e => e.Email).HasColumnName("email");
            entity.Property(e => e.Password).HasColumnName("password_hash");
            entity.Property(e => e.CreatedAt).HasColumnName("created_at");
        });

        modelBuilder.Entity<Category>(entity =>
        {
            entity.ToTable("categories");
            entity.Property(e => e.Id).HasColumnName("id");
            entity.Property(e => e.UserId).HasColumnName("user_id");
            entity.Property(e => e.Name).HasColumnName("name");
            entity.Property(e => e.Type).HasColumnName("type");
            entity.Property(e => e.Icon).HasColumnName("icon");
            entity.Property(e => e.Color).HasColumnName("color");
            entity.Property(e => e.CreatedAt).HasColumnName("created_at");
        });

        modelBuilder.Entity<Transaction>(entity =>
        {
            entity.ToTable("transactions");
            entity.Property(e => e.Id).HasColumnName("id");
            entity.Property(e => e.UserId).HasColumnName("user_id");
            entity.Property(e => e.CategoryId).HasColumnName("category_id");
            entity.Property(e => e.Amount).HasColumnName("amount");
            entity.Property(e => e.Type).HasColumnName("type");
            entity.Property(e => e.Note).HasColumnName("note");
            entity.Property(e => e.CreatedAt).HasColumnName("created_at");
        });
    }
}
