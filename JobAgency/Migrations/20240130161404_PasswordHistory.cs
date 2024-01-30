using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace JobAgency.Migrations
{
    public partial class PasswordHistory : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTime>(
                name: "PasswordExpirationDate",
                table: "AspNetUsers",
                type: "datetime2",
                nullable: true);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "PasswordExpirationDate",
                table: "AspNetUsers");
        }
    }
}
