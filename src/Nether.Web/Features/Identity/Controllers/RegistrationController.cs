using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Logging;
using Nether.Data.Identity;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace Nether.Web.Features.Identity.Controllers
{
    [AllowAnonymous]
    [Route("api/registration")]
    public class RegistrationController : Controller
    {
        private readonly IUserStore _userStore;
        private readonly IPasswordHasher _passwordHasher;
        private readonly ILogger _logger;

        public RegistrationController(
            IUserStore userStore,
            IPasswordHasher passwordHasher,
            ILogger<RegistrationController> logger
        )
        {
            _userStore = userStore;
            _passwordHasher = passwordHasher;
            _logger = logger;
        }

        [HttpPost("device")]
        public async Task<IActionResult> Post([FromBody]string deviceId)
        {
            _logger.LogInformation($"Registering device {deviceId}");

            var user = await _userStore.GetUserByLoginAsync(LoginProvider.UserNamePassword, deviceId);
            if (user != null)
            {
                throw new ArgumentException($"User with deviceId is already registered");
            }

            user = new User();
            user.IsActive = true;
            user.Role = RoleNames.Player;
            user.Logins = new List<Login>();
            await _userStore.SaveUserAsync(user);
            string providerId = deviceId;
            string userId = deviceId;
            string providerType = LoginProvider.UserNamePassword;
            string password = Guid.NewGuid().ToString("d");
            var login = new Login()
            {
                ProviderId = providerId,
                ProviderType = providerType,
                ProviderData =  _passwordHasher.HashPassword(password)
            };
            user.Logins.Add(login);
            await _userStore.SaveUserAsync(user);
            return Json(new { password });
        }
    }
}
