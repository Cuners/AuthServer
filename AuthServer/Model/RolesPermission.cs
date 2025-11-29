using System.Data;

namespace AuthServer.Model
{
    public partial class RolesPermission
    {
        public int RolePermissionId { get; set; }

        public int? RoleId { get; set; }

        public int? PermissionId { get; set; }

        public virtual Permission? Permission { get; set; }

        public virtual Role? Role { get; set; }
    }
}
