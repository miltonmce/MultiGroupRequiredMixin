from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied

class MultiGroupRequiredMixin(LoginRequiredMixin):
    """
    Este mixin verifica si el usuario está autenticado y pertenece a uno de los grupos requeridos.
    Confía en los permisos ya asignados a los grupos desde el admin de Django.
    """
    allowed_groups = None  # Lista de grupos permitidos.
    permission_denied_message = "No tienes permiso para acceder a esta página."

    def get_allowed_groups(self):
        """
        Retorna la lista de grupos permitidos. Si no se define, se lanza una excepción.
        """
        if self.allowed_groups is None:
            raise ValueError(
                "El atributo 'allowed_groups' debe ser especificado en la vista "
                "como una lista o tupla de nombres de grupos."
            )
        if not isinstance(self.allowed_groups, (list, tuple)):
            raise ValueError(
                "El atributo 'allowed_groups' debe ser una lista o tupla."
            )
        return self.allowed_groups

    def get_permission_denied_message(self):
        """
        Retorna el mensaje de error personalizado.
        """
        return self.permission_denied_message

    def has_group_permission(self, user, allowed_groups):
        """
        Verifica si el usuario pertenece a alguno de los grupos permitidos o es superusuario.
        """
        return user.is_superuser or user.groups.filter(name__in=allowed_groups).exists()

    def dispatch(self, request, *args, **kwargs):
        # Verifica si el usuario está autenticado (usando LoginRequiredMixin)
        if not request.user.is_authenticated:
            return self.handle_no_permission()

        # Obtiene los grupos permitidos
        allowed_groups = self.get_allowed_groups()

        # Verifica si el usuario pertenece a alguno de los grupos permitidos
        if not self.has_group_permission(request.user, allowed_groups):
            raise PermissionDenied(self.get_permission_denied_message())

        # Si pasa ambas verificaciones, permite el acceso a la vista
        return super().dispatch(request, *args, **kwargs)
