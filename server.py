from flask import Flask, request
from werkzeug.utils import secure_filename
import subprocess
import json
import os
import time

UPLOAD_FOLDER = "./uploads"
CMD_BASE = "python ./VxAPI/vxapi.py"
ARGUMENTS = "--no-share-third-party 1 --allow-community-access 0"

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


@app.route("/quick-scan-url", methods=['POST'])
def quick_scan_url():
    url = request.form['url']
    cmd_arguments = " scan_url_for_analysis " + ARGUMENTS + " " + \
        url + " scan_urlscanio"
    return executeCommand(cmd_arguments)


@app.route("/quick-scan-url-file", methods=['POST'])
def quick_scan_url_file():
    url_file = request.form['url_file']
    cmd_arguments = " scan_url_to_file " + ARGUMENTS + " " + \
        url_file + " scan_metadefender"
    return executeCommand(cmd_arguments)


@app.route("/quick-scan-file", methods=['POST'])
def quick_scan_file():
    f = request.files['file']
    filename = secure_filename(f.filename)
    f.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    cmd_arguments = " scan_file " + ARGUMENTS + " " + \
        filename + " scan_metadefender"
    print(filename)
    result = executeCommand(cmd_arguments)
    os.remove("./uploads/" + filename)
    return result


@app.route("/sandbox-url", methods=['POST'])
def sandbox_url():
    url = request.form['url']
    cmd_arguments = " submit_url_for_analysis " + ARGUMENTS + " " + \
        url + " 120"
    return executeSandbox(cmd_arguments)


@app.route("/sandbox-url-file", methods=['POST'])
def sandbox_url_file():
    url_file = request.form['url-file']
    cmd_arguments = " submit_url_to_file " + ARGUMENTS + " " + \
        url_file + " 120"
    return executeSandbox(cmd_arguments)


@app.route("/sandbox-file", methods=['POST'])
def sandbox_file():
    f = request.files['file']
    filename = secure_filename(f.filename)
    f.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    cmd_arguments = " submit_file " + ARGUMENTS + " " + \
        filename + " 120"
    verdict = executeSandbox(cmd_arguments)
    os.remove("./uploads/" + filename)
    return verdict


def executeCommand(cmd_arguments):
    cmd = CMD_BASE + cmd_arguments
    result = subprocess.run(cmd, capture_output=True, text=True)
    stdout = result.stdout
    stderr = result.stderr
    print(stdout)
    print(stderr)
    return getScanResult(stdout)


def executeSandbox(cmd_arguments):
    cmd = CMD_BASE + cmd_arguments
    result = subprocess.run(cmd, capture_output=True, text=True)
    stdout = result.stdout
    stderr = result.stderr
    print(stdout)
    print(stderr)
    job_id = json.loads(stdout)["job_id"]
    job_done = False
    timeout = 0
    while (job_done is False and timeout < 10):
        time.sleep(6)
        if (getSandboxState(job_id)):
            job_done = True
        timeout += 1
    if (timeout >= 10):
        return "Timeout exceeded"
    return getSandboxSummary(job_id)


def getSandboxState(job_id):
    cmd = CMD_BASE + " report_get_state " + job_id
    result = subprocess.run(cmd, capture_output=True, text=True)
    stdout = result.stdout
    stderr = result.stderr
    status = json.loads(stdout)["state"]
    return status == "SUCCESS"


def getSandboxSummary(job_id):
    cmd = CMD_BASE + " report_get_summary " + job_id
    result = subprocess.run(cmd, capture_output=True, text=True)
    stdout = result.stdout
    stderr = result.stderr
    verdict = json.loads(stdout)["state"]
    return verdict


def getScanResult(scan_report):
    json_report = json.loads(scan_report)
    json_report = json_report["scanners"]
    json_report = json_report[0]
    json_report = json_report["status"]
    return json_report
