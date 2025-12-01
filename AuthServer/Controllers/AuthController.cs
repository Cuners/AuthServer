using AuthServer.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
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
        private readonly IConfiguration _configuration;
        public AuthController(AuthTestContext authtestContext, IConfiguration configuration)
        {
            _authtestContext = authtestContext;
            _configuration = configuration;
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

                //if (!VerifyPassword(login.Password, user.PassHash))
                //{
                //    return Unauthorized("Invalid password.");
                //}

                var token = GenerateJwtToken(user);
                return Ok(new { token });
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
            var token = GenerateJwtToken(user);
            return Ok(new { token });
            //return Ok(user);
        }
        private string GenerateJwtToken(User user)
        {
            var jwtSettings = _configuration.GetSection("JwtSettings");
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Login),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };
            foreach (var ur in user.UsersRoles)
            {
                claims.Add(new Claim(ClaimTypes.Role, ur.Role.RoleName));
            }

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings["SecretKey"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: jwtSettings["Issuer"],
                audience: jwtSettings["Audience"],
                claims: claims,
                expires: DateTime.Now.AddMinutes(30),
                signingCredentials: creds);
            var tokenString = new JwtSecurityTokenHandler().WriteToken(token);
            Response.Cookies.Append("cookie-now", tokenString);
            return tokenString;
        }

        private bool VerifyPassword(string password, string storedHash)
        {
            using (var sha256 = SHA256.Create()) 
            { 
                var computedHash = sha256.ComputeHash(Encoding.UTF8.GetBytes(password)); 
                return computedHash.SequenceEqual(Convert.FromBase64String(storedHash)); 
            }
            // return BCrypt.Net.BCrypt.Verify(password, storedHash);
        }
    }

}
