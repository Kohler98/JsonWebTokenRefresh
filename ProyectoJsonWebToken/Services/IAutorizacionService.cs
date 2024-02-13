using ProyectoJsonWebToken.Models.Custom;
namespace ProyectoJsonWebToken.Services
{
    public interface IAutorizacionService
    {

        Task<AutorizationResponse> DevolverToken(AutorizacionRequest autorizacion);
        Task<AutorizationResponse> DevolverRefreshToken(RefreshTokenRequest refreshTokenRequest, int idUsuario);
 
    }
}
