using AuthServer.Model;
using System.Security.Claims;

namespace AuthServer.Services
{
    public interface ITokenService
    {
        List<Claim> GenerateUserClaims(User user);

        string GenerateAccessToken(IEnumerable<Claim> claims);
        string GenerateRefreshToken(IEnumerable<Claim> claims);

        string RefreshTokens(string oldRefreshToken, out string newRefreshToken);
    }
}
