using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Logging;
using Nether.Data.Identity;
using Nether.Data.PlayerManagement;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace Nether.Web.Features.Identity.Controllers
{
    [AllowAnonymous]
    [Route("registration")]
    public class RegistrationController : Controller
    {
        private readonly IUserStore _userStore;
        private readonly IPasswordHasher _passwordHasher;
        private readonly ILogger _logger;
        private readonly IPlayerManagementStore _playerStore;

        public RegistrationController(
            IUserStore userStore,
            IPasswordHasher passwordHasher,
            ILogger<RegistrationController> logger,
            IPlayerManagementStore playerStore
        )
        {
            _userStore = userStore;
            _playerStore = playerStore;
            _passwordHasher = passwordHasher;
            _logger = logger;
        }

        [HttpPost("device")]
        public async Task<IActionResult> Post([FromBody]Login login)
        {
            _logger.LogInformation($"Registering device {login.ProviderId}");

            var user = await _userStore.GetUserByLoginAsync(LoginProvider.UserNamePassword, login.ProviderId);
            if (user != null)
            {
                throw new ArgumentException($"User with deviceId is already registered");
            }

            user = new User();
            user.IsActive = true;
            user.Role = RoleNames.Player;
            user.Logins = new List<Login>();
            await _userStore.SaveUserAsync(user);
            login.ProviderType = LoginProvider.UserNamePassword;
            string password = Guid.NewGuid().ToString("d");
            login.ProviderData = _passwordHasher.HashPassword(password);
            user.Logins.Add(login);
            await _userStore.SaveUserAsync(user);
            // return non hashed password once to let client store it
            login.ProviderData = password;

            var player = new Player();
            player.UserId = user.UserId;
            player.Gamertag = login.ProviderId;

            await _playerStore.SavePlayerAsync(player);
            
            return Json(login);
        }
    }
}
