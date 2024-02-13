using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using ProyectoJsonWebToken.Models.Custom;
using ProyectoJsonWebToken.Services;
using System.IdentityModel.Tokens.Jwt;

namespace ProyectoJsonWebToken.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UsuarioController : ControllerBase
    {
        private readonly IAutorizacionService _autorizacionService;

        public UsuarioController(IAutorizacionService autorizacionService)
        {
            _autorizacionService = autorizacionService;
        }
        [HttpPost]
        [Route("Autenticar")]
        public async Task<IActionResult> Autenticar([FromBody] AutorizacionRequest autorizacion)
        {
            var resultado_autorizacion = await _autorizacionService.DevolverToken(autorizacion);

            if (resultado_autorizacion == null)
            {
                return Unauthorized(new AutorizationResponse { Resultado = false, Msg = "El token no ha expirado" });

            }
            return Ok(resultado_autorizacion);
        }        
        [HttpPost]
        [Route("ObtenerRefreshToken")]
        public async Task<IActionResult> ObtenerRefreshToken([FromBody] RefreshTokenRequest request)
        {
            var token_handler = new JwtSecurityTokenHandler();

            var token_expirado = token_handler.ReadJwtToken(request.TokenExpirado);

            if(token_expirado.ValidTo > DateTime.UtcNow)
            {
                return BadRequest(new AutorizationResponse { Resultado = false, Msg = "El token no ha expirado" });
            }
            string idUsuario = token_expirado.Claims.First(x =>

                x.Type == JwtRegisteredClaimNames.NameId).Value.ToString();

            var autorizacion_response = await _autorizacionService.DevolverRefreshToken(request,int.Parse(idUsuario));

            if (autorizacion_response.Resultado)
            {
                return Ok(autorizacion_response);
            }
            else
            {
                return BadRequest(autorizacion_response);
            }


        }
    }
}
