from flask import Flask, render_template, request, jsonify, send_file
import io
import re
import shlex
from dockerfile_parse import DockerfileParser
import nvdlib
import time
import json
import subprocess
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
api_key = 'API_KEY'
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024 #2MB max file size
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def parse_base_image(value):
    """Extract the base image and version from a FROM instruction."""
    value = value.strip(' "\'')
    value = re.sub(r'\s*:\s*', ':', value.strip())
    if " AS " in value.upper():
        base_part, _alias = re.split(r'\s+AS\s+', value, flags=re.IGNORECASE)
    else:
        base_part = value
    if ':' in base_part:
        tech, version = base_part.split(':', 1)
        version = version.strip()
        if version.startswith('v'):
            version = version[1:]
    else:
        tech = base_part
        version = 'latest'
    return (tech, version)

def parse_pip_packages(packages_str):
    """
    Extract pip packages from a pip install command string.
    Uses shlex.split() to correctly handle quoted tokens.
    Returns a list of (package, version) tuples.
    """
    # Use shlex.split to properly split the command while respecting quotes.
    tokens = shlex.split(packages_str)
    results = []
    for token in tokens:
        token = token.strip()
        if not token or token == "\\" or token.startswith('-'):
            continue
        # Check for exact version pinning with '=='
        if '==' in token:
            name, version = token.split('==', 1)
        # Check for other version constraints (>=, <=, <, >, ~=) all in one token
        elif re.search(r'[><=~]', token):
            match = re.match(r'^([A-Za-z0-9_\-\.]+)([><=~].*)', token)
            if match:
                name = match.group(1)
                version = match.group(2)
            else:
                name, version = token, 'latest'
        else:
            name, version = token, 'latest'
        results.append((name, version))
    return results

def parse_apt_packages(packages_str):
    """
    Extract apt (or apk) packages from an install command string.
    Returns a list of (package, version) tuples.
    """
    tokens = packages_str.split()
    results = []
    for token in tokens:
        token = token.strip(' "\'')
        if not token or token.startswith('-'):
            continue
        if '=' in token:
            name, version = token.split('=', 1)
        else:
            name, version = token, 'latest'
        results.append((name, version))
    return results

def search_cpe(tech_array, api_key):
    final_array = []
    for tech in tech_array:
        tech_name = tech.split(":")[0]
        tech_version = tech.split(":")[1]

        if tech_version != "":
            print("Searching for CPEs for", tech_name + ":" + tech_version + "...")
        else:
            print("Searching for CPEs for", tech_name + "...")
        max_retries = 5
        for attempt in range(max_retries):
            try:
                r = nvdlib.searchCPE(keywordSearch=tech_name + " " + tech_version, key=api_key, delay=2)
                break
            except Exception as e:
                print(f"Attempt {attempt+1} failed in searchCPE: {e}")
                time.sleep(2*attempt)
        else:
            print("All retries failed for searchCPE")
            return []
        array_r = []
        for eachCPE in r:
            if(tech_version != ""):
                if((tech_name+":"+tech_version) in eachCPE.cpeName and eachCPE.deprecated == False):
                    version_index = eachCPE.cpeName.find(tech_version)
                    colon_index = eachCPE.cpeName.find(":", version_index)
                    version_length = colon_index - version_index
                    if((not((version_length > len(tech_version)) and (eachCPE.cpeName[version_index+version_length - 1] != "0"))) and (((eachCPE.cpeName[colon_index+1]) == "-") or (eachCPE.cpeName[colon_index+1]) == "*") and ((version_length - len(tech_version)) <= 2)):
                        array_r.append(eachCPE.cpeName)
            else:
                index = eachCPE.cpeName.rfind(tech_name)
                array_r.append(eachCPE.cpeName)

        array_r.sort()
        if(tech_version != ""):
            print("Found CPEs:", array_r)
            final_array.extend(array_r)
        else:
            try:
                print("No version provided, using latest CPE available:", array_r[-1])
                final_array.append(array_r[-1])
            except IndexError:
                print("No CPEs found for", tech_name)
    print("FINAL ARRAY:", final_array)
    return final_array

def search_cves(cpes, api_key):
    print("Searching for CVEs regarding CPEs:", cpes)
    cve_array_temp = []
    for cpe in cpes:
        max_retries = 5
        for attempt in range(max_retries):
            try:
                r = nvdlib.searchCVE(cpeName=cpe, key=api_key, delay=2)
                break
            except Exception as e:
                print(f"Attempt {attempt+1} for {cpe} in searchCVE failed: {e}")
                time.sleep(2)
        else:
            print(f"All retries failed for searchCVE for {cpe}")
            continue
        for eachCVE in r:
            print(eachCVE.id)
            print(str((eachCVE.descriptions[0]))[25:-2])
            cve_array_temp.append(eachCVE.id + ": " + str((eachCVE.descriptions[0]))[25:-2])
    return cve_array_temp

def generate_cyclonedx_sbom(components, app_name="dockerfile-sbom", app_version="1.0.0"):
    """
    Generates a minimal CycloneDX SBOM JSON-like dictionary from a list of
    {'technology': x, 'version': y} dicts.
    """
    # Build the basic SBOM structure
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": app_name,
                "version": app_version
            }
        },
        "components": []
    }

    # add sbom components
    for c in components:
        sbom["components"].append({
            "type": "library",
            "name": c["technology"],
            "description": c["version"]
        })

    return sbom

def check_file(file):
    if(not(file)):
       print("No file uploaded.")
       return False
    if(file.name.includes('.')):
        print("File must not have an extension.")
        return False
    if(scan_file(file) != True):
        return False
    return True

def scan_file(file_path):
    """Scan file using clamscan command-line tool"""
    print(f"[DEBUG] Starting scan of file: {file_path}")
    try:
        # check if clamscan is available
        version_check = subprocess.run(
            ['clamscan', '--version'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5
        )
        print(f"[DEBUG] ClamAV version: {version_check.stdout.strip()}")
        
        # creates the clam scan command
        command = ['clamscan', '--no-summary', '--bell', str(file_path)]
        print(f"[DEBUG] Executing command: {' '.join(command)}")
        
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30
        )
        
        print(f"[DEBUG] Return code: {result.returncode}")
        print(f"[DEBUG] stdout: {result.stdout}")
        print(f"[DEBUG] stderr: {result.stderr}")
        
        if result.returncode == 0:
            print("[DEBUG] Scan completed successfully - no threats found")
            return True, "File clean"
        elif result.returncode == 1:
            print(f"[DEBUG] Threat detected: {result.stdout}")
            return False, f"Infected: {result.stdout}"
        else:
            error_msg = result.stderr or f"Unknown error (code {result.returncode})"
            print(f"[DEBUG] Scan failed with error: {error_msg}")
            return False, error_msg
            
    except subprocess.TimeoutExpired as te:
        print(f"[DEBUG] Scan timed out after {te.timeout} seconds")
        return False, "Scan timed out"
    except FileNotFoundError:
        print("[DEBUG] Error: ClamAV not installed or not in PATH")
        return False, "ClamAV antivirus is not installed"
    except Exception as e:
        print(f"[DEBUG] Unexpected error: {str(e)}")
        return False, f"Scan error: {str(e)}"
    

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload():
    uploaded_file = request.files.get('file')
    if uploaded_file:
        # Create uploads directory if it doesn't exist
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        
        # Save the file to a temporary location
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(uploaded_file.filename))
        uploaded_file.save(temp_path)
        
        try:
            # Scan the saved file
            scan_result, scan_message = scan_file(temp_path)
            if not scan_result:
                os.remove(temp_path)  # Clean up
                return f"File scan failed: {scan_message}"
            
            # Read the contents after scanning
            with open(temp_path, 'r') as f:
                file_text = f.read()
            
            # Parse the Dockerfile using dockerfile-parse
            parser = DockerfileParser(fileobj=io.StringIO(file_text))
            instructions = parser.structure

            # array to store all found technologies
            technologies = []

            for instr in instructions:
                inst = instr['instruction'].upper()
                value = instr['value']
                if inst == 'FROM':
                    tech, version = parse_base_image(value)
                    technologies.append({'technology': tech, 'version': version})
                elif inst == 'RUN':
                    # Split the RUN command into segments by both "&&" and ";".
                    segments = re.split(r'&&|;', value)
                    for segment in segments:
                        segment = segment.strip()
                        if not segment:
                            continue
                        # Process apt-get install commands
                        if 'apt-get install' in segment:
                            apt_match = re.search(r'apt-get\s+install\s+-y\s+(.*)', segment, re.IGNORECASE)
                            if apt_match:
                                packages_str = apt_match.group(1)
                                apt_pkgs = parse_apt_packages(packages_str)
                                for pkg in apt_pkgs:
                                    technologies.append({'technology': pkg[0], 'version': pkg[1]})
                        # Process apk add commands (for Alpine)
                        elif 'apk add' in segment:
                            apk_match = re.search(r'apk\s+add\s+(?:--no-cache\s+)?(.*)', segment, re.IGNORECASE)
                            if apk_match:
                                packages_str = apk_match.group(1)
                                apk_pkgs = parse_apt_packages(packages_str)
                                for pkg in apk_pkgs:
                                    technologies.append({'technology': pkg[0], 'version': pkg[1]})
                        # Process pip install commands
                        elif 'pip install' in segment:
                            pip_match = re.search(r'pip\s+install\s+(.*)', segment, re.IGNORECASE)
                            if pip_match:
                                packages_str = pip_match.group(1)
                                pip_pkgs = parse_pip_packages(packages_str)
                                for pkg in pip_pkgs:
                                    technologies.append({'technology': pkg[0], 'version': pkg[1]})

            tech_version_list = []
            for tech in technologies:
                version = tech['version']
                if ',' in version:
                    upper_bound = version.split(',')[-1].strip()
                    upper_bound = re.sub(r'^[^0-9\.]+', '', upper_bound)
                    version = upper_bound
                tech_version_list.append(f"{tech['technology'].lower()}:{version}")

            cpe_array = search_cpe(tech_version_list, api_key)
            cve_array = search_cves(cpe_array, api_key)

            formatted_lines = []
            for item in cve_array:
                parts = item.split(":", 1)
                if len(parts) == 2:
                    formatted_line = f"{parts[0].strip()}: {parts[1].strip()}"
                else:
                    formatted_line = item
                formatted_lines.append(formatted_line)

            components = []
            for item in cve_array:
                tech, version = item.split(":", 1)
                components.append({"technology": tech, "version": version.strip()})
            sbom = generate_cyclonedx_sbom(components)
            sbom_formatted = json.dumps(json.loads(json.dumps(sbom)), indent=2)

            # Clean up the temporary file
            os.remove(temp_path)

            return render_template('results.html',
                                technologies=technologies,
                                dockerfile_content=file_text,
                                cpes=cpe_array,
                                cves=formatted_lines,
                                sbom=sbom_formatted)

        except Exception as e:
            # Clean up on error
            if os.path.exists(temp_path):
                os.remove(temp_path)
            return f"Error processing file: {str(e)}"

    return "No file uploaded."

@app.route('/download_sbom', methods=['POST'])
def download_sbom():
    sbom_data = request.form.get('sbom_data')
    if sbom_data:
        mem = io.BytesIO()
        mem.write(sbom_data.encode('utf-8'))
        mem.seek(0)
        return send_file(
            mem,
            mimetype='application/json',
            as_attachment=True,
            download_name='sbom.json'
        )
    return "No SBOM data provided", 400


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
