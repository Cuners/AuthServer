using System;
using System.Collections.Generic;

namespace AuthServer.Model
{
    public partial class User
    {
        public int UserId { get; set; }
        public string? Login { get; set; }
        public string? PassHash { get; set; }
        public int? RoleId { get; set; }
    }
}
