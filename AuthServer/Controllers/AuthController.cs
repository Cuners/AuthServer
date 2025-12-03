using AuthServer.Model;
using AuthServer.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace AuthServer.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : Controller
    {
        private AuthTestContext? _authtestContext;
        private readonly ITokenService _tokenService;
        public AuthController(AuthTestContext authtestContext, ITokenService tokenService)
        {
            _authtestContext = authtestContext;
            _tokenService = tokenService;
        }
        [Authorize(Policy="Get")]
        [HttpGet]
        [Route("/getUsers")]
        public async Task<ActionResult<IEnumerable<User>>> Get()
        {

            return await _authtestContext.Users.ToListAsync();
        }   
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest login)
        {
            if (string.IsNullOrWhiteSpace(login?.Username) || string.IsNullOrWhiteSpace(login?.Password))
            {
                return BadRequest("Username and password are required.");
            }

            try
            {
                var user = await _authtestContext.Users
                                .Include(u => u.UsersRoles)
                                .ThenInclude(ur => ur.Role)
                                .FirstOrDefaultAsync(u => u.Login == login.Username);

                if (user == null)
                {
                    return Unauthorized("Invalid username.");
                }
                var claims = _tokenService.GenerateUserClaims(user);

                var accesstoken = _tokenService.GenerateAccessToken(claims);
                var refreshtoken = _tokenService.GenerateRefreshToken(claims);

                SetCookies(accesstoken, refreshtoken);

                return Ok(new { accesstoken });
            }
            catch (Exception EX)
            {
                return StatusCode(500, EX.Message);
            }
        }
        [HttpPost("registration")]
        public async Task<ActionResult<IEnumerable<User>>> Registration(User user)
        {
            if (user == null)
            {
                return BadRequest();
            }
            
            _authtestContext.Users.Add(user);
            var role = await _authtestContext.Roles
                             .FirstOrDefaultAsync(r => r.RoleName == "User");

            user.UsersRoles.Add(new UsersRole
            {
                RoleId = role.RoleId
            });

            await _authtestContext.SaveChangesAsync();
            var claims = _tokenService.GenerateUserClaims(user);
            var accesstoken = _tokenService.GenerateAccessToken(claims);
            var refreshtoken = _tokenService.GenerateRefreshToken(claims);

            SetCookies(accesstoken, refreshtoken);
            return Ok(new { accesstoken });
            //return Ok(user);
        }
        [HttpPost("logout")]
        public async Task<IActionResult> Logout()
        {
            if (!Request.Cookies.TryGetValue("refresh_token", out var refreshToken))
            {
                return Ok("No active session");
            }
            Response.Cookies.Delete("access_token");
            Response.Cookies.Delete("refresh_token");
            return Ok("Logged out");
        }
        [HttpPost("refresh")]
        public IActionResult Refresh()
        {
            if (!Request.Cookies.TryGetValue("refresh_token", out var refreshToken))
                return Unauthorized();
            var access = _tokenService.RefreshTokens(refreshToken, out var newRefresh);

            SetCookies(access, newRefresh);

            return Ok("Refreshed");
        }


        private void SetCookies(string access, string refresh)
        {
            Response.Cookies.Append("access_token", access, new CookieOptions
            {
                HttpOnly = true,
                Expires = DateTime.UtcNow.AddMinutes(15),
                SameSite = SameSiteMode.Strict,
                Secure = true
            });

            Response.Cookies.Append("refresh_token", refresh, new CookieOptions
            {
                HttpOnly = true,
                Expires = DateTime.UtcNow.AddDays(7),
                SameSite = SameSiteMode.Strict,
                Secure = true
            });
        }
        private bool VerifyPassword(string password, string storedHash)
        {
            using (var sha256 = SHA256.Create()) 
            { 
                var computedHash = sha256.ComputeHash(Encoding.UTF8.GetBytes(password)); 
                return computedHash.SequenceEqual(Convert.FromBase64String(storedHash)); 
            }
        }
    }

}
