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
            ClockSkew = TimeSpan.FromMinutes(5)
        };
    });

builder.Services.AddAuthorization();

// CORS - Allow any origin for simplicity
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

// CORS must come before Authentication
app.UseCors("AllowAll");

// Token blacklist middleware
app.Use(async (context, next) =>
{
    var cache = context.RequestServices.GetRequiredService<IMemoryCache>();
    var authHeader = context.Request.Headers["Authorization"].ToString();

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
                context.Response.StatusCode = 401;
                await context.Response.WriteAsJsonAsync(new { error = "Token has been revoked" });
                return;
            }
        }
        catch { }
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

// -------- REGISTER --------
app.MapPost("/register", async (MyDbContext db, User user) =>
{
    try
    {
        if (await db.Users.AnyAsync(u => u.Email == user.Email))
            return Results.BadRequest(new { error = "Email already registered" });

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
app.MapPost("/logout", async (HttpContext context, IMemoryCache cache) =>
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
            .Select(c => new { c.Id, c.Name })
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

// -------- BUDGETS --------
app.MapGet("/budgets", [Authorize] async (ClaimsPrincipal user, MyDbContext db) =>
{
    try
    {
        var idStr = user.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!Guid.TryParse(idStr, out var userId)) return Results.Problem("Invalid user ID", statusCode: 401);

        var budgets = await db.Budgets
            .Where(b => b.UserId == userId)
            .OrderByDescending(b => b.Year)
            .ThenByDescending(b => b.Month)
            .ToListAsync();

        return Results.Ok(budgets);
    }
    catch (Exception ex)
    {
        Console.WriteLine($"❌ Budgets error: {ex.Message}");
        return Results.Problem($"Error fetching budgets: {ex.Message}", statusCode: 500);
    }
}).RequireAuthorization();

app.MapPost("/budgets", [Authorize] async (ClaimsPrincipal user, MyDbContext db, BudgetRequest req) =>
{
    try
    {
        var idStr = user.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!Guid.TryParse(idStr, out var userId)) return Results.Problem("Invalid user ID", statusCode: 401);

        var category = await db.Categories.FindAsync(req.CategoryId);
        if (category == null || category.UserId != userId)
            return Results.BadRequest(new { error = "Invalid category" });

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
    }
    catch (Exception ex)
    {
        Console.WriteLine($"❌ Create budget error: {ex.Message}");
        return Results.Problem($"Error creating budget: {ex.Message}", statusCode: 500);
    }
}).RequireAuthorization();

// -------- TRANSACTIONS --------
app.MapPost("/add-transaction", [Authorize] async (ClaimsPrincipal user, MyDbContext db, TransactionRequest req) =>
{
    try
    {
        var idStr = user.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!Guid.TryParse(idStr, out var userId))
        {
            Console.WriteLine($"❌ Invalid user ID from token: {idStr}");
            return Results.Problem("Invalid user ID", statusCode: 401);
        }

        if (!Guid.TryParse(req.CategoryId, out var categoryId))
        {
            Console.WriteLine($"❌ Invalid category ID format: {req.CategoryId}");
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
            Console.WriteLine($"❌ Category {categoryId} belongs to user {category.UserId}, not {userId}");
            return Results.BadRequest(new { error = "Invalid category" });
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

        db.Transactions.Add(transaction);
        await db.SaveChangesAsync();

        var response = new
        {
            id = transaction.Id.ToString(),
            amount = transaction.Amount,
            type = transaction.Type,
            note = transaction.Note,
            createdAt = transaction.CreatedAt.ToString("o"),
            categoryName = category.Name
        };

        Console.WriteLine($"✅ Transaction created successfully: {transaction.Id}");
        return Results.Ok(new { message = "Transaction added successfully", transaction = response });
    }
    catch (Exception ex)
    {
        Console.WriteLine($"❌ Add transaction error: {ex.Message}");
        Console.WriteLine($"Stack trace: {ex.StackTrace}");
        return Results.Problem($"Error adding transaction: {ex.Message}", statusCode: 500);
    }
}).RequireAuthorization();

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
                    t.Type,
                    t.Note,
                    t.CreatedAt,
                    CategoryName = c.Name
                })
            .OrderByDescending(t => t.CreatedAt)
            .ToListAsync();

        var transactions = rawTransactions.Select(t => new
        {
            id = t.Id.ToString(),
            amount = t.Amount,
            type = t.Type,
            note = t.Note,
            createdAt = t.CreatedAt.ToString("o"),
            categoryName = t.CategoryName
        });

        return Results.Ok(transactions);
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
    public string Type { get; set; } = null!;
    public string? Icon { get; set; }
    public string? Color { get; set; }
    public DateTime CreatedAt { get; set; }
}

public class CategoryRequest
{
    public string Name { get; set; } = null!;
    public string Type { get; set; } = null!;
    public string? Icon { get; set; }
    public string? Color { get; set; }
}

public class Budget
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public Guid CategoryId { get; set; }
    public int Month { get; set; }
    public int Year { get; set; }
    public decimal LimitAmount { get; set; }
    public DateTime CreatedAt { get; set; }
}

public class BudgetRequest
{
    public Guid CategoryId { get; set; }
    public int Month { get; set; }
    public int Year { get; set; }
    public decimal LimitAmount { get; set; }
}

public class TransactionRequest
{
    public string CategoryId { get; set; } = null!;
    public decimal Amount { get; set; }
    public string Type { get; set; } = null!;
    public string? Note { get; set; }
}

public class Transaction
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public Guid CategoryId { get; set; }
    public decimal Amount { get; set; }
    public string Type { get; set; } = null!;
    public string Note { get; set; } = "";
    public DateTime CreatedAt { get; set; }
}

// ================= DB CONTEXT =================
public class MyDbContext : DbContext
{
    public MyDbContext(DbContextOptions<MyDbContext> options) : base(options) { }

    public DbSet<User> Users { get; set; } = null!;
    public DbSet<Category> Categories { get; set; } = null!;
    public DbSet<Budget> Budgets { get; set; } = null!;
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

        modelBuilder.Entity<Budget>(entity =>
        {
            entity.ToTable("budgets");
            entity.Property(e => e.Id).HasColumnName("id");
            entity.Property(e => e.UserId).HasColumnName("user_id");
            entity.Property(e => e.CategoryId).HasColumnName("category_id");
            entity.Property(e => e.Month).HasColumnName("month");
            entity.Property(e => e.Year).HasColumnName("year");
            entity.Property(e => e.LimitAmount).HasColumnName("limit_amount");
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
