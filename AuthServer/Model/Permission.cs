namespace AuthServer.Model
{
    public partial class Permission
    {
        public int PermissionId { get; set; }

        public string? PermissionName { get; set; }

        public virtual ICollection<RolesPermission> RolesPermissions { get; set; } = new List<RolesPermission>();
    }
}
