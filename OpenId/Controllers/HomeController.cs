using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using OpenId.Models;
using OpenId.Services;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace OpenId.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        private const string clientId = "TestClient";
        private const string redirectUri = "http://localhost:8080/realms/Test/account/Callback";
        private const string configUrl = "http://localhost:8080/realms/master/.well-known/openid-configuration";
        private const string clientSecret = "uIbQKQh7I1k4xAW66SOMhx5Nn1MzJpsn";
        private Dictionary<string, object> config = new();

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        [HttpGet("/login")]
        public async Task<IActionResult> Login()
        {
            using var http = new HttpClient();
            config = await http.GetFromJsonAsync<Dictionary<string, object>>(configUrl);
            var authorizationEndpoint = config["authorization_endpoint"]?.ToString();

            var state = GenerateRandomString();
            var codeVerifier = GenerateRandomString();
            var codeChallenge = GenerateCodeChallenge(codeVerifier);

            OAuthCache.StoreCodeVerifier(state, codeVerifier);

            var parameters = new Dictionary<string, string?>
        {
            { "client_id", clientId },
            { "scope", "openid email phone address profile" },
            { "response_type", "code" },
            { "redirect_uri", redirectUri },
            { "prompt", "login" },
            { "state", state },
            { "code_challenge_method", "S256" },
            { "code_challenge", codeChallenge }
        };

            var authorizationUri = QueryHelpers.AddQueryString(authorizationEndpoint!, parameters);
            return Redirect(authorizationUri);
        }

        [HttpGet("/realms/Test/account/Callback")]
        public async Task<IActionResult> Callback(AuthorizationResponse query)
        {
            var (state, code) = query;
            var codeVerifier = OAuthCache.GetCodeVerifier(state);

            var tokenResponse = await ExchangeCodeForTokens(code, codeVerifier);
            if (tokenResponse == null)
            {
                return BadRequest("Failed to exchange code for tokens");
            }

            var accessToken = tokenResponse.access_token;
            var idToken = tokenResponse.id_token;

            bool isIdTokenValid = await VerifyIdToken(idToken);
            if (!isIdTokenValid)
            {
                return BadRequest("Invalid ID token");
            }

            var userInfo = await FetchUserInfo(accessToken);
            if (userInfo == null)
            {
                return BadRequest("Failed to fetch user information");
            }

            HttpContext.Session.SetString("UserInfo", JsonConvert.SerializeObject(userInfo));

            return RedirectToAction("Dashboard", "Home");
        }

        private async Task<TokenResponse> ExchangeCodeForTokens(string code, string codeVerifier)
        {
            var parameters = new Dictionary<string, string?>
            {
                { "grant_type", "authorization_code" },
                { "code", code }, // The authorization code received from Keycloak
                { "redirect_uri", redirectUri },
                { "code_verifier", codeVerifier }, 
                { "client_id", clientId }, 
                { "client_secret", clientSecret }
            };

            string tokenEndpoint = config["token_endpoint"]?.ToString();
            var response = await new HttpClient().PostAsync(tokenEndpoint, new FormUrlEncodedContent(parameters));

            if (response.IsSuccessStatusCode)
            {
                var payload = await response.Content.ReadFromJsonAsync<TokenResponse>();
                return payload ?? throw new Exception("Failed to exchange code for tokens");
            }
            else
            {
                throw new Exception("Token exchange failed");
            }
        }

        private async Task<object?> FetchUserInfo(string accessToken)
        {
            var http = new HttpClient
            {
                DefaultRequestHeaders =
                {
                    { "Authorization", "Bearer " + accessToken }
                }
            };

            string userinfoEndpoint = config["userinfo_endpoint"]?.ToString();
            var response = await http.GetAsync(userinfoEndpoint);
            var content = await response.Content.ReadFromJsonAsync<object?>();

            return content;
        }

        private async Task<bool> VerifyIdToken(string idToken)
        {
            string jwksUri = config["jwks_uri"]?.ToString();
            var response = await new HttpClient().GetAsync(jwksUri);
            var keys = await response.Content.ReadAsStringAsync();
            var jwks = JsonWebKeySet.Create(keys);
            jwks.SkipUnresolvedJsonWebKeys = false;

            var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
            var token = handler.ReadJwtToken(idToken);

            var validationParameters = new TokenValidationParameters
            {
                IssuerSigningKeys = jwks.GetSigningKeys(),
                ValidIssuer = "http://localhost:8080/realms/master",
                ValidateIssuer = true,
                ValidateAudience = false,
                ValidateLifetime = true
            };

            try
            {
                handler.ValidateToken(idToken, validationParameters, out var validatedToken);
                return true;
            }
            catch
            {
                return false; 
            }
        }

        private static string GenerateRandomString(int length = 64)
        {
            var bytes = new byte[length];
            RandomNumberGenerator.Fill(bytes);

            return Convert.ToBase64String(bytes)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_'); 
        }

        private static string GenerateCodeChallenge(string codeVerifier)
        {
            using var sha256 = SHA256.Create();
            var bytes = Encoding.ASCII.GetBytes(codeVerifier);
            var hash = sha256.ComputeHash(bytes);

            return Convert.ToBase64String(hash)
                .TrimEnd('=') // Remove padding
                .Replace('+', '-') // URL-safe '+'
                .Replace('/', '_'); // URL-safe '/'
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
