using JwtAuthApi.Context;
using JwtAuthApi.Helper;
using JwtAuthApi.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JwtAuthApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly AppDbContext _context;
        public UserController(AppDbContext appDbContext)
        {
            _context = appDbContext;
        }
        [Authorize]
        [HttpGet]
        public async Task<ActionResult<User>> GetAllUsers()
        {
            return Ok( await _context.Users.ToListAsync() );
        }
        [HttpPost("authenticate")]
        public async Task<IActionResult> Authenticate([FromBody] User userObject)
        {
            if(userObject == null)
            {
                return BadRequest();
            }
            var user = await _context.Users.FirstOrDefaultAsync(x  => x.Email == userObject.Email);
            if(user == null) {
                return NotFound(new {Message = "User doesn't exist !"});
            }

            if(!PasswordHasher.VerifyPassword(userObject.Password, user.Password))
            {
                return BadRequest(new { Message = "Wrong password !" });
            }
            user.Token = CreateJwt(user);
            return Ok(new {
                Token=user.Token,
                Message = "Connected successfully!"
            });
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] User userObject)
        {
            if(userObject == null)
            {
                return BadRequest();
            }

            //Check Email
            if (await checkEmailExist(userObject.Email))
            {
                return BadRequest(new { Message = "Email already exists !" });
            }

            userObject.Password = PasswordHasher.HashPassword(userObject.Password);
            userObject.Role = "User";
            userObject.Token = "";
            await _context.Users.AddAsync(userObject);
            await _context.SaveChangesAsync();
            return Ok(new {Message = "Registred Succesfully !"});

        }

        private async Task<bool> checkEmailExist(string email)
        {
            return await _context.Users.AnyAsync(x => x.Email == email);
        }

        private string CreateJwt(User user)
        {
            var JwtTokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("this_is_a_32_byte_secret_key_that_is_super_secure");
            var identity = new ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.Role , user.Role),
                new Claim(ClaimTypes.Name , user.Username)
            });
            var credentials = new SigningCredentials(new SymmetricSecurityKey(key) , SecurityAlgorithms.HmacSha256);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = identity,
                Expires = DateTime.Now.AddDays(1),
                SigningCredentials = credentials
            };
            var token = JwtTokenHandler.CreateToken(tokenDescriptor);
            return JwtTokenHandler.WriteToken(token);
        }
    }
}
