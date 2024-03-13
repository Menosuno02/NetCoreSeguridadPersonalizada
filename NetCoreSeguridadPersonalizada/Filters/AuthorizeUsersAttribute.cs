using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace NetCoreSeguridadPersonalizada.Filters
{
    public class AuthorizeUsersAttribute
        : AuthorizeAttribute, IAuthorizationFilter
    {
        // Este método impedirá acceder a las zonas
        // que hayamos decorado
        // Dicho filter debe validar si existimos
        // en la app o no
        // Si no estamos validados en nuestra App,
        // nos llevará a Login
        // Si estamos validados, no hacemos nada
        public void OnAuthorization(AuthorizationFilterContext context)
        {
            // El usuario estará dentro de HttpContext
            // y su propiedad User
            // Ese usuario pertenece a la clase principal
            // e Identity
            // Mediante la identidad podemos saber el nombre
            // del user y mediante el principal el role
            var user = context.HttpContext.User;
            // Preguntamos si el user ya está autentificado
            if (!user.Identity.IsAuthenticated)
            {
                // Creamos la ruta a nuestra dirección
                RouteValueDictionary rutaLogin =
                    new RouteValueDictionary
                    (
                        new { controller = "Managed", action = "Login" }
                    );
                // Llevamos al usuario a login
                context.Result =
                    new RedirectToRouteResult(rutaLogin);
            }
        }
    }
}
