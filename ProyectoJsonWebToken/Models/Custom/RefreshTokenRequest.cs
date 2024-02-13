using System.Security.Cryptography.X509Certificates;

namespace ProyectoJsonWebToken.Models.Custom
{
    public class RefreshTokenRequest
    {

        public string TokenExpirado {  get; set; }
        public string RefreshToken {  get; set; }
    }
}
