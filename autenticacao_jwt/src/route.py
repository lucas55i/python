from logging import Logger
import token
from flask import Blueprint, jsonify, request
import jwt
from datetime import datetime, timedelta

route_bp = Blueprint('route', __name__)


@route_bp.route("/secret", methods=["GET"])
def secret_route():
    raw_token = request.headers.get("Authorization")
    uid = request.headers.get("uid")

    if not raw_token or not uid:
        return jsonify({
            'error': "Não Autorizado"
        }), 401

    try:
        token = raw_token.split()[1]
        token_information = jwt.decode(token, key="1234", algorithms="HS256")
        token_uid = token_information['uid']
    except jwt.InvalidSignatureError:
        return jsonify({
            'error': "Token Invalido"
        }), 401
    except jwt.ExpiredSignatureError:
        return jsonify({
            'error': "Token Expirado"
        }), 401
    except KeyError as e:
        return jsonify({
            'error': "Token Invalido2"
        }), 401

    if int(token_uid) != int(uid):
        return jsonify({
            'error': "Usuário Não Permitido"
        }), 401

    # Devemos chegar aqui
    return jsonify({
        'data': 'Mensagem secreta',
    }), 200


@route_bp.route("/auth", methods=["POST"])
def authorization_route():
    token = jwt.encode({
        'exp': datetime.utcnow() + timedelta(minutes=30),
        'uid': 12
    }, key='1234', algorithm="HS256")

    return jsonify({
        'token': token
    }), 200
