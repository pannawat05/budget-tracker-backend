# --- Build Stage (ใช้ SDK) ---
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# คัดลอก .csproj และ restore
COPY *.csproj .
RUN dotnet restore

# คัดลอกโค้ดที่เหลือและ Build
COPY . .
RUN dotnet publish "server.csproj" -c Release -o /app/out

# --- Final Stage (ใช้ ASP.NET Runtime) ---
FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY --from=build /app/out .

# คำสั่งเริ่มต้นแอป (ไม่ต้องใช้ entrypoint แล้ว)
CMD ["dotnet", "server.dll"]
