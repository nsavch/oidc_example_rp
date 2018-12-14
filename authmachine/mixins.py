from django.core.exceptions import PermissionDenied


class PermissionRequiredMixin:
    permission = None

    def dispatch(self, request, *args, **kwargs):
        if not (request.user.is_authenticated and self.permission in request.session.get('permissions', [])):
            raise PermissionDenied()
        return super().dispatch(request, *args, **kwargs)
