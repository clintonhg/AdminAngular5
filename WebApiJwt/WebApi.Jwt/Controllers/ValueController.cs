using System.Web.Http;
using WebApi.Jwt.Filters;
using WebApi.Jwt.Models;

namespace WebApi.Jwt.Controllers
{
    //[EnableCors(origins: "http://mywebclient.azurewebsites.net", headers: "*", methods: "*")] personalisado   
    public class ValueController : ApiController
    {
        [JwtAuthentication]
        public string Get2()
        {
            return "EXITOSO";
        }

        [HttpGet]
        [AllowAnonymous]
        public GenericResult<UserInfo> prueba()
        {
            var result = new GenericResult<UserInfo>();
            var obj = new UserInfo{
                Username="clinton autorizado"
            };
            result.Result = obj;
            return result;
        }

        [HttpGet]
        [AllowAnonymous]
        public string prueba2(string name)
        {
            return "prueba exitosa " + name;
        }
    }
}
