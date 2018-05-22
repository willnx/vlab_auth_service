# -*- coding: UTF-8 -*-
from flask import Flask
from vlab_auth_service.lib.views import HealthView, TokenView, KeyView

app = Flask(__name__)

HealthView.register(app)
TokenView.register(app)
KeyView.register(app)


if __name__ == '__main__':
    app.run(host="0.0.0.0", debug=True)
