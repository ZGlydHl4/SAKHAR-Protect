from flask import Flask, request
from werkzeug.utils import secure_filename
import subprocess
import json
import os

UPLOAD_FOLDER = "./uploads"

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


@app.route("/quick-scan-url", methods=['POST'])
def quick_scan_url():
    url = request.form['url']
    cmd_arguments = " scan_url_for_analysis --no-share-third-party 1 --allow-community-access 0 " + \
        url + " scan_urlscanio"
    return executeCommand(cmd_arguments)


@app.route("/quick-scan-url-file", methods=['POST'])
def quick_scan_url_file():
    url_file = request.form['url_file']
    cmd_arguments = " scan_url_to_file --no-share-third-party 1 --allow-community-access 0 " + \
        url_file + " scan_metadefender"
    return executeCommand(cmd_arguments)


@app.route("/quick-scan-file", methods=['POST'])
def quick_scan_file():
    f = request.files['file']
    filename = secure_filename(f.filename)
    f.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    cmd_arguments = " scan_file --no-share-third-party 1 --allow-community-access 0 ./uploads/" + \
        filename + " scan_metadefender"
    result = executeCommand(cmd_arguments)
    os.remove("./uploads/" + filename)
    return result


@app.route("/sandbox-url", methods=['POST'])
def sandbox_url():
    url = request.form['url']
    cmd_arguments = " submit_url_for_analysis --no-share-third-party 1 --allow-community-access 0 " + \
        url + " 120"
    return executeSandbox(cmd_arguments)


def executeCommand(cmd_arguments):
    cmd_base = "python ./VxAPI/vxapi.py"
    cmd = cmd_base + cmd_arguments
    result = subprocess.run(cmd, capture_output=True, text=True)
    stdout = result.stdout
    stderr = result.stderr
    print(stdout)
    print(stderr)
    return getScanResult(stdout)


def executeSandbox(cmd_arguments):
    cmd_base = "python ./VxAPI/vxapi.py"
    cmd = cmd_base + cmd_arguments
    result = subprocess.run(cmd, capture_output=True, text=True)
    stdout = result.stdout
    stderr = result.stderr
    print(stdout)
    print(stderr)
    return ""


def getScanResult(scan_report):
    json_report = json.loads(scan_report)
    json_report = json_report["scanners"]
    json_report = json_report[0]
    json_report = json_report["status"]
    return json_report
