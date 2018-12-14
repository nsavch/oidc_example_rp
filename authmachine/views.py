from django.contrib import auth
from django.http import HttpResponseRedirect, HttpResponseForbidden

from .client import AuthMachineClient

User = auth.get_user_model()


def login(request):
    """Redirects user to AuthMachine site for authentication."""
    next = request.GET.get('next') or '/'
    auth_url = AuthMachineClient(request).get_authorization_url(request, next=next)
    return HttpResponseRedirect(auth_url)


def logout(request):
    """Logout user."""
    auth.logout(request)
    request.session['user'] = None
    return HttpResponseRedirect('/')


def sso_callback(request):
    client = AuthMachineClient(request)
    aresp = client.get_authorization_response(request)
    user_info = client.get_userinfo(aresp)

    username = user_info['userName']
    request.session['user'] = {'username': username}
    try:
        user = User.objects.get(username=username)
        # raise RuntimeError('%s %s' % (user.username, user_info))
    except User.DoesNotExist:
        user = User.objects.create(username=username, email=user_info['email'])
    auth.login(request, user)

    state = client.get_state(request, aresp)
    return HttpResponseRedirect(state.get('next') or '/')
