using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;
using System;
using System.Collections.Generic;
using System.Data;
using System.Security;

namespace AuthServer.Model
{
    public partial class AuthTestContext : DbContext
    {
        public AuthTestContext()
        {
        }

        public AuthTestContext(DbContextOptions<AuthTestContext> options)
            : base(options)
        {
        }

        public virtual DbSet<Permission> Permissions { get; set; }

        public virtual DbSet<Role> Roles { get; set; }

        public virtual DbSet<RolesPermission> RolesPermissions { get; set; }

        public virtual DbSet<User> Users { get; set; }

        public virtual DbSet<UsersRole> UsersRoles { get; set; }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
#warning To protect potentially sensitive information in your connection string, you should move it out of source code. You can avoid scaffolding the connection string by using the Name= syntax to read it from configuration - see https://go.microsoft.com/fwlink/?linkid=2131148. For more guidance on storing connection strings, see https://go.microsoft.com/fwlink/?LinkId=723263.
            => optionsBuilder.UseSqlServer("Server=DESKTOP-N4N6HD1;Database=AuthTest;Trusted_Connection=True;TrustServerCertificate=True;MultipleActiveResultSets=true");

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<RolesPermission>(entity =>
            {
                entity.HasKey(e => e.RolePermissionId);

                entity.HasOne(d => d.Permission).WithMany(p => p.RolesPermissions)
                    .HasForeignKey(d => d.PermissionId)
                    .HasConstraintName("FK_RolesPermissions_Permissions");

                entity.HasOne(d => d.Role).WithMany(p => p.RolesPermissions)
                    .HasForeignKey(d => d.RoleId)
                    .HasConstraintName("FK_RolesPermissions_Roles");
            });

            modelBuilder.Entity<UsersRole>(entity =>
            {
                entity.HasKey(e => e.UserRoleId);

                entity.HasOne(d => d.Role).WithMany(p => p.UsersRoles)
                    .HasForeignKey(d => d.RoleId)
                    .HasConstraintName("FK_UsersRoles_Roles");

                entity.HasOne(d => d.User).WithMany(p => p.UsersRoles)
                    .HasForeignKey(d => d.UserId)
                    .HasConstraintName("FK_UsersRoles_Users");
            });

            OnModelCreatingPartial(modelBuilder);
        }

        partial void OnModelCreatingPartial(ModelBuilder modelBuilder);
    }
}
