from flask import Flask, request
from werkzeug.utils import secure_filename
import subprocess
import json
import os

cmd_template = "python ./VxAPI/vxapi.py"
UPLOAD_FOLDER = "./uploads"

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


@app.route("/quick-scan-url", methods=['POST'])
def quick_scan_url():
    url = request.form['url']
    cmd = cmd_template + " scan_url_for_analysis --no-share-third-party 1 --allow-community-access 0 " + \
        url + " scan_urlscanio"
    result = subprocess.run(cmd, capture_output=True, text=True)
    stdout = result.stdout
    stderr = result.stderr
    return getScanResult(stdout)


@app.route("/quick-scan-url-file", methods=['POST'])
def quick_scan_url_file():
    url_file = request.form['url_file']
    cmd = cmd_template + " scan_url_to_file --no-share-third-party 1 --allow-community-access 0 " + \
        url_file + " scan_metadefender"
    result = subprocess.run(cmd, capture_output=True, text=True)
    stdout = result.stdout
    stderr = result.stderr
    return getScanResult(stdout)


@app.route("/quick-scan-file", methods=['POST'])
def quick_scan_file():
    f = request.files['file']
    filename = secure_filename(f.filename)
    f.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    cmd = cmd_template + " scan_file --no-share-third-party 1 --allow-community-access 0 ./uploads/" + \
        filename + " scan_metadefender"
    result = subprocess.run(cmd, capture_output=True, text=True)
    stdout = result.stdout
    stderr = result.stderr
    os.remove("./uploads/" + filename)
    return getScanResult(stdout)


def getScanResult(scan_report):
    json_report = json.loads(scan_report)
    json_report = json_report["scanners"]
    json_report = json_report[0]
    json_report = json_report["status"]
    return json_report
