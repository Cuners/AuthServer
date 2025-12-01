using AuthServer.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using System.Security.Claims;

namespace AuthServer.Infrastructure.Authorization
{
    public class PermissionHandler : AuthorizationHandler<PermissionRequirement>
    {
        private readonly AuthTestContext _authtestContext;
        private readonly IMemoryCache _cache;

        public PermissionHandler(AuthTestContext authtestContext, IMemoryCache cache)
        {
            _authtestContext = authtestContext;
            _cache = cache;
        }

        protected override async Task HandleRequirementAsync(
            AuthorizationHandlerContext context,
            PermissionRequirement requirement)
        {
            // роли из токена
            var roles = context.User.Claims
                  .Where(c => c.Type == ClaimTypes.Role)
                  .Select(c => c.Value)
                  .ToList();

            if (!roles.Any())
                return;

            // Ключ для кэша
            var cacheKey = $"perms:{string.Join(",", roles)}";

            // Permissions из кеша, если есть
            var permissions = await _cache.GetOrCreateAsync(cacheKey, async entry =>
            {
                entry.AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(5);
                var perm = await _authtestContext.RolesPermissions
                    .Where(rp => roles.Contains(rp.Role.RoleName))
                    .Select(rp => rp.Permission.PermissionName)
                    .Distinct()
                    .ToListAsync();
                // Загружаем permissions для всех ролей
                return perm;
            });

            // проверка
            if (permissions.Contains(requirement.Permission))
            {
                context.Succeed(requirement);
            }
        }
    }
}
