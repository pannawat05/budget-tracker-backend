# --- Build Stage (ใช้ SDK) ---
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# คัดลอก .csproj และ restore
COPY *.csproj .
RUN dotnet restore

# คัดลอกโค้ดที่เหลือและ Build
COPY . .
RUN dotnet publish "YourApiProjectName.csproj" -c Release -o /app/out

### 1. ติดตั้ง EF Tools ไว้ในโฟลเดอร์แยก ###
RUN dotnet tool install --global dotnet-ef --tool-path /tools


# --- Final Stage (ใช้ ASP.NET Runtime) ---
FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY --from=build /app/out .

### 2. คัดลอก EF Tools ที่ติดตั้งไว้มาใส่ใน Image สุดท้าย ###
COPY --from=build /tools /tools
ENV PATH="$PATH:/tools"

### 3. คัดลอก Entrypoint Script และทำให้มันทำงานได้ ###
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

### 4. ตั้งค่าให้ Entrypoint ชี้ไปที่สคริปต์ของเรา ###
# และ CMD คือคำสั่งปกติที่จะถูกส่งไปให้สคริปต์
ENTRYPOINT ["/bin/bash", "entrypoint.sh"]
CMD ["dotnet", "server.dll"]
