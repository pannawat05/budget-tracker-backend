#!/bin/bash
# ทำให้สคริปต์หยุดทำงานทันทีถ้ามีคำสั่งไหนพลาด
set -e

# สั่งรัน Database Migration
echo "Applying database migrations..."
dotnet ef database update

# ถ้าสำเร็จ...
echo "Migrations applied successfully."

# รันคำสั่งหลักที่ส่งมาจาก Dockerfile (คือ `dotnet YourApiProjectName.dll`)
exec "$@"
