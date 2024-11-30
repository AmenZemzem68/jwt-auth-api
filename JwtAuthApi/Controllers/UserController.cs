using JwtAuthApi.Context;
using JwtAuthApi.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

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
        [HttpPost("authenticate")]
        public async Task<IActionResult> Authenticate([FromBody] User userObject)
        {
            if(userObject == null)
            {
                return BadRequest();
            }

            var user = await _context.Users.FirstOrDefaultAsync(x  => x.Email == userObject.Email && x.Password == userObject.Password);
            if(user == null) {
                return NotFound(new {Message = "Not Found !"});
            }
            return Ok(new {Message = "Connected successfully!"});
        }
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] User userObject)
        {
            if(userObject == null)
            {
                return BadRequest();
            }
            userObject.Role = "User";
            userObject.Token = "";
            await _context.Users.AddAsync(userObject);
            await _context.SaveChangesAsync();
            return Ok(new {Message = "User added succefully"});

        }
    }
}
