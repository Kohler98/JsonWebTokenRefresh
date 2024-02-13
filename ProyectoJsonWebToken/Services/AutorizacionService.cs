using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using ProyectoJsonWebToken.Models;
using ProyectoJsonWebToken.Models.Custom;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;

namespace ProyectoJsonWebToken.Services
{
    public class AutorizacionService : IAutorizacionService
    {
        private readonly IConfiguration _configuration;
        private readonly DbpruebaContext _context;

        public AutorizacionService(IConfiguration configuration, DbpruebaContext context)
        {
            _configuration = configuration;
            _context = context;
        }

        private string GenerarToken(string idUsuario)
        {
            var key = _configuration.GetValue<string>("JwtSetting:Key");
            var keyBytes = Encoding.ASCII.GetBytes(key);

            var claims = new ClaimsIdentity();
            claims.AddClaim(new Claim(ClaimTypes.NameIdentifier, idUsuario));

            var creadencialesToken = new SigningCredentials(
                new SymmetricSecurityKey(keyBytes),
                SecurityAlgorithms.HmacSha256Signature
                );

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = claims,
                Expires = DateTime.UtcNow.AddMinutes(1),
                SigningCredentials = creadencialesToken,
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenConfig = tokenHandler.CreateToken(tokenDescriptor);

            string tokenCreado = tokenHandler.WriteToken(tokenConfig);

            return tokenCreado;
        }

        public async Task<AutorizationResponse> DevolverToken(AutorizacionRequest autorizacion)
        {
            var usuario_encontrado = _context.Usuarios.FirstOrDefault(x =>

                x.NombreUsuario == autorizacion.NombreUsuario && 
                x.Clave == autorizacion.Clave
            );

            if(usuario_encontrado == null)
            {
                return await Task.FromResult<AutorizationResponse >(null);
            }

            string tokenCreado = GenerarToken(usuario_encontrado.IdUsuario.ToString());
            string refreshTokenCreado = GenerarRefreshToken();
            //return new AutorizationResponse() { Token = tokenCreado, Resultado = true, Msg = "OK" };

            return await GuardarHistorialRefreshToken(usuario_encontrado.IdUsuario, tokenCreado, refreshTokenCreado);
        }
        private string GenerarRefreshToken()
        {
            var byteArray = new byte[64];
            var refreshToken = "";

            using (var mg = RandomNumberGenerator.Create())
            {
                mg.GetBytes(byteArray);
                refreshToken = Convert.ToBase64String(byteArray);

            }
            return refreshToken;
        }

        private async Task <AutorizationResponse> GuardarHistorialRefreshToken(
            int idUsuario,
            string token,
            string refreshToken)
        {
            var historialRefreshToken = new HistorialRefreshToken
            {
                IdUsuario = idUsuario,
                Token = token,
                RefreshToken = refreshToken,
                FechaCreacion = DateTime.UtcNow,
                FechaExpiracion = DateTime.UtcNow.AddMinutes(2)
            };

            await _context.HistorialRefreshTokens.AddAsync(historialRefreshToken);
            await _context.SaveChangesAsync();

            return new AutorizationResponse { Token = token, Resultado = true,Msg = "OK" };
        }
        public async Task<AutorizationResponse> DevolverRefreshToken(RefreshTokenRequest refreshTokenRequest, int idUsuario)
        {
            var refreshToken_encontrado = _context.HistorialRefreshTokens.FirstOrDefault(x =>
                x.Token == refreshTokenRequest.TokenExpirado &&
                x.RefreshToken == refreshTokenRequest.RefreshToken &&
                x.IdUsuario == idUsuario
            );

            if(refreshToken_encontrado  == null)
            {
                return new AutorizationResponse { Resultado = false, Msg = "no existe el refresh token" };

               
            }
            var refreshTokenCreado = GenerarRefreshToken();

            var tokenCreado = GenerarToken(idUsuario.ToString());

            return await GuardarHistorialRefreshToken(idUsuario, tokenCreado, refreshTokenCreado);
        }
    }
}
