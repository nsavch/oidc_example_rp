def add_permissions(request):
    return {
        'permissions': request.session.get('permissions', [])
    }
