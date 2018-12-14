import bjoern
from oidc_example_rp.wsgi import application

bjoern.run(application, '0.0.0.0', 8080)
