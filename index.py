from flask import request, jsonify, Response
from flask import Flask
from flask_basicauth import BasicAuth
import psutil

app = Flask(__name__)
app.config['BASIC_AUTH_USERNAME'] = 'sdi'
app.config['BASIC_AUTH_PASSWORD'] = 'admin'

secure_my_api = BasicAuth(app)

def getVmStatus():
    cpu = psutil.cpu_percent(interval=1)
    vram = psutil.virtual_memory()
    disk = psutil.disk_usage("C:")
    return {"cpu": cpu, "mem":vram.percent, "disk":disk.percent}

@app.route('/lab1', methods=["GET"])
def lab1():
    return 'Welcome to Lab1'

@app.route('/lab2', methods=["POST"])
def lab2():
    content = request.get_json()
    print content
    result = {}
    result['department'] = content['department']
    result['id'] = content['id']
    result['name'] = content['name']
    result['status'] = 200
    return jsonify(result)

@app.route('/api/v1/vm1/cpu', methods=["GET"])
@secure_my_api.required
def cpu():
    status = getVmStatus()
    res = {}
    res['cpu%'] = status["cpu"]
    return jsonify(res)

@app.route('/api/v1/vm1/mem', methods=["GET"])
@secure_my_api.required
def mem():
    status = getVmStatus()
    res = {}
    res['mem%'] = status["mem"]
    return jsonify(res)

@app.route('/api/v1/vm1/disk', methods=["GET"])
@secure_my_api.required
def disk():
    status = getVmStatus()
    res = {}
    res['disk%'] = status["disk"]
    return jsonify(res)

@app.route('/api/v1/vm1', methods=["GET"])
@secure_my_api.required
def vm1():

    status = getVmStatus()
    res = {}
    res['vm1%'] = status
    return jsonify(res)

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=80)