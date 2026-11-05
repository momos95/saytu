import hashlib
import os
import pickle
import ssl
import subprocess

import requests
import yaml


def commands(name):
    # ruleid: saytu.python.command-injection
    os.system("ls " + name)
    # ruleid: saytu.python.command-injection
    subprocess.run(f"grep {name} /etc/hosts", shell=True)
    # ok: saytu.python.command-injection
    subprocess.run(["grep", name, "/etc/hosts"])
    # ok: saytu.python.command-injection
    os.system("uptime")


def sql(cursor, user_id, name):
    # ruleid: saytu.python.sql-injection
    cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)
    # ruleid: saytu.python.sql-injection
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
    # ruleid: saytu.python.sql-injection
    cursor.execute("SELECT * FROM users WHERE name = '{}'".format(name))
    # ok: saytu.python.sql-injection
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    query = "DELETE FROM t WHERE id = %s" % user_id
    # ruleid: saytu.python.sql-injection
    cursor.execute(query)


def deser(data, path):
    # ruleid: saytu.python.unsafe-deserialization
    pickle.loads(data)
    # ruleid: saytu.python.unsafe-deserialization
    yaml.load(data)
    # ruleid: saytu.python.unsafe-deserialization
    yaml.load(data, Loader=yaml.Loader)
    # ok: saytu.python.unsafe-deserialization
    yaml.load(data, Loader=yaml.SafeLoader)
    # ok: saytu.python.unsafe-deserialization
    yaml.safe_load(data)


def tls(url):
    # ruleid: saytu.python.tls-verification-disabled
    requests.get(url, verify=False)
    # ruleid: saytu.python.tls-verification-disabled
    ssl._create_unverified_context()
    # ok: saytu.python.tls-verification-disabled
    requests.get(url, verify="/etc/ssl/internal-ca.pem")


def hashes(data):
    # ruleid: saytu.python.weak-hash
    hashlib.md5(data)
    # ruleid: saytu.python.weak-hash
    hashlib.new("sha1", data)
    # ok: saytu.python.weak-hash
    hashlib.md5(data, usedforsecurity=False)
    # ok: saytu.python.weak-hash
    hashlib.sha256(data)


def main(app):
    # ruleid: saytu.python.flask-debug
    app.run(host="0.0.0.0", debug=True)
    # ok: saytu.python.flask-debug
    app.run(host="127.0.0.1")
