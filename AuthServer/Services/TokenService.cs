using AuthServer.Model;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AuthServer.Services
{
    public class TokenService : ITokenService   
    {
        private readonly IConfiguration _config;

        public TokenService(IConfiguration config)
        {
            _config = config;
        }

        public List<Claim> GenerateUserClaims(User user)
        {
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Login),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            foreach (var role in user.UsersRoles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role.Role.RoleName));
            }

            return claims;
        }

        public string GenerateAccessToken(IEnumerable<Claim> claims)
        {
            return CreateToken(claims, DateTime.UtcNow.AddMinutes(15));
        }

        public string GenerateRefreshToken(IEnumerable<Claim> claims)
        {
            return CreateToken(claims, DateTime.UtcNow.AddDays(7));
        }

        private string CreateToken(IEnumerable<Claim> claims, DateTime expires)
        {
            var settings = _config.GetSection("JwtSettings");
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(settings["SecretKey"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: settings["Issuer"],
                audience: settings["Audience"],
                claims: claims,
                expires: expires,
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public string RefreshTokens(string oldRefreshToken, out string newRefreshToken)
        {
            var handler = new JwtSecurityTokenHandler();
            var jwt = handler.ReadJwtToken(oldRefreshToken);

            var claims = jwt.Claims.ToList();

            var access = GenerateAccessToken(claims);
            newRefreshToken = GenerateRefreshToken(claims);

            return access;

        }

    }
}
