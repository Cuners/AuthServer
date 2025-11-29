namespace AuthServer.Model
{
    public partial class Role
    {
        public int RoleId { get; set; }

        public string? RoleName { get; set; }

        public virtual ICollection<RolesPermission> RolesPermissions { get; set; } = new List<RolesPermission>();

        public virtual ICollection<UsersRole> UsersRoles { get; set; } = new List<UsersRole>();
    }

}
