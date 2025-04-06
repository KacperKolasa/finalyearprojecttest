from flask import Flask, render_template, request, jsonify, send_file, Response
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
from packaging import version as pkg_version
import docker
import tarfile
import tempfile
import shutil

app = Flask(__name__)
api_key = 'a50fcc56-0781-4abc-956a-cfabd358deea'
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024 # 2MB max file size for uploads
UPLOAD_FOLDER = 'uploads' # Creates a folder named 'uploads' in the current directory
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER # sets the upload folder to the one created above

def parse_base_image(value):
    value = value.strip(' "\'') 
    value = re.sub(r'\s*:\s*', ':', value.strip()) # strip received string
    if " AS " in value.upper():
        base_part, _alias = re.split(r'\s+AS\s+', value, flags=re.IGNORECASE)
    else:
        base_part = value
    if ':' in base_part: # splits into name and version
        tech, version = base_part.split(':', 1)
        version = version.strip()
        if version.startswith('v'):
            version = version[1:]
        if version != 'latest' and '-' in version:
            candidate = version.split('-')[0] # remove suffixes like -alpine, -slim
            if candidate and candidate[0].isdigit():
                version = candidate
    else:
        tech = base_part
        version = 'latest' # if no version is specified, set it to 'latest'
    return (tech, version)

def parse_pip_packages(packages_str):
    packages = shlex.split(packages_str) # splits command into indiviudal packages
    results = []
    for package in packages: # iterates over each package
        package = package.strip()
        if not package or package == "\\" or package.startswith('-'): # skips empty packages or those starting with '-'
            continue
        if package.lower() in ["pip", "install"]: # skips pip and install commands
            continue
        if '==' in package: # == specifies an exact version
            name, version = package.split('==', 1)
        elif re.search(r'[><=~]', package): # uses a regular expression to seperate name and version
            match = re.match(r'^([A-Za-z0-9_\-\.]+)([><=~].*)', package)
            if match:
                name = match.group(1)
                version = match.group(2)
            else:
                name, version = package, 'latest' # if no match, set to latest
        else:
            name, version = package, 'latest' # if no version is specified, set to latest
        results.append((name, version))
    return results

def parse_apt_packages(packages_str):
    packages = packages_str.split() # splits command into indiviudal packages
    results = []
    for package in packages:
        package = package.strip(' "\'') # cleans up the package name
        if not package or package.startswith('-'): # skips empty packages or those starting with '-'
            continue
        if '=' in package:
            name, version = package.split('=', 1) # splits into name and version
        else:
            name, version = package, 'latest' # if no version is specified, set to latest
        results.append((name, version))
    return results


def generate_version_array(v):
    version_array = []
    if not v or v == "latest":
        return None
    if '.' not in v: # if theres no dot, extend the version with .0 and .0.0 to match more CPEs
        version_array = [v, v + ".0", v + ".0.0"]
    parts = v.split('.')
    if len(parts) == 2:
        version_array = [v, v + ".0"]
    # If v already has at least two dots, return it as-is.
    return version_array

def search_cpe(tech_array, api_key):
    final_array = []
    for tech in tech_array:
        tech_name, tech_version = tech.split(":", 1) # split string to get name and version separately
        tech_name = tech_name.replace("*", "").lower().strip()
        tech_version = tech_version.strip().lower()
        version_array = generate_version_array(tech_version) # generates an array of versions to search for, eg 9 -> [9, 9.0, 9.0.0]
        
        if tech_version and tech_version != "latest": # if version is specified, search for it
            print("Searching for CPEs for", f"{tech_name}:{tech_version}...")
        else: # if version is latest, then search for all cpes for the technology
            print("Searching for CPEs for", tech_name + "...")
        
        max_retries = 5 
        for attempt in range(max_retries): # retry logic for API call
            try:
                keyword = tech_name + " " + (tech_version if tech_version and tech_version != "latest" else "")
                r = nvdlib.searchCPE(keywordSearch=keyword, key=api_key, delay=2) # search for CPEs using nvdlib api
                break
            except Exception as e:
                print(f"Attempt {attempt+1} failed in searchCPE: {e}")
                time.sleep(2 * attempt)
        else:
            print("All retries failed for searchCPE")
            return []

        array_r = [] # array to store the cpes found
        if version_array is not None:
            vendor_group = {} # dictionary to group cpes by vendor
            for eachCPE in r: 
                if eachCPE.deprecated: # skips deprecated cpes
                    continue
                cpe_str = eachCPE.cpeName.lower()
                parts = cpe_str.split(':')
                if len(parts) < 7:
                    continue
                vendor = parts[3].strip()     # vendor is field index 3
                product = parts[4].strip()    # product is field index 4
                cpe_version = parts[5].strip()  # version is field index 5
                update_field = parts[6].strip() # update is field index 6

                if product != tech_name: # skips cpes that do not match the technology name exactly
                    continue
                if cpe_version not in version_array: # skips cpes that do not match the versions specified
                    continue
                if vendor not in vendor_group: # if there is no cpe with this vendor in the dictionary, add it
                    vendor_group[vendor] = eachCPE.cpeName
                else: # if vendor is already present, compare update fields to decide which to keep
                    current_parts = vendor_group[vendor].lower().split(':')
                    current_update = current_parts[6].strip() if len(current_parts) >= 7 else ""
                    if current_update != "*" and update_field == "*":
                        vendor_group[vendor] = eachCPE.cpeName
                    elif current_update != "-" and update_field == "-":
                        vendor_group[vendor] = eachCPE.cpeName
            array_r = list(vendor_group.values())
            array_r.sort()
            print("Found CPEs:", array_r)
            final_array.extend(array_r)
        else: # If no version is specified, search for all cpes and choose highest version
            pattern = re.compile(r'\b' + re.escape(tech_name) + r':[0-9]+', re.IGNORECASE) # regex pattern to find the technology name with a version after it
            vendor_groups = {}
            for eachCPE in r:
                if eachCPE.deprecated:
                    continue
                if not pattern.search(eachCPE.cpeName):
                    continue
                parts = eachCPE.cpeName.split(':')
                if len(parts) < 6:
                    continue
                vendor = parts[3].lower().strip()
                ver_str = parts[5].lower().strip()
                if ver_str in ['-', '*', '']: # skips versions that are not valid such as * or - or empty
                    continue
                try:
                    parsed_ver = pkg_version.parse(ver_str)
                except Exception as ex:
                    continue
                vendor_groups.setdefault(vendor, []).append((parsed_ver, ver_str, eachCPE.cpeName)) # groups cpes by vendor and stores the version and cpe name in a tuple
            for vendor, items in vendor_groups.items(): # take latest version
                items.sort(key=lambda x: x[0], reverse=True)
                latest_cpe = items[0][2]
                array_r.append(latest_cpe)
            array_r.sort()
            print("Found CPEs (latest for each vendor):", array_r)
            final_array.extend(array_r)
    print("FINAL ARRAY:", final_array)
    return final_array

def search_cves(cpes, api_key):
    print("Searching for CVEs regarding CPEs:", cpes)
    cve_array_temp = [] # list to store the cves found
    for cpe in cpes:
        max_retries = 5
        for attempt in range(max_retries): # retry logic for api calls
            try:
                r = nvdlib.searchCVE(cpeName=cpe, key=api_key, delay=2) # search for cves using nvdlib api
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
            cve_array_temp.append(eachCVE.id + ": " + str((eachCVE.descriptions[0]))[25:-2]) # adds the cve id and description to the list
    return cve_array_temp

def generate_cyclonedx_sbom(components, app_name="dockerfile-sbom", app_version="1.0.0"):
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
            "name": c["id"],
            "description": c["desc"]
        })

    return sbom

def check_file(file):
    if(not(file)):
       print("No file uploaded.")
       return False
    if(file.name.includes('.')): # checks if the file has an extension
        print("File must not have an extension.")
        return False
    if(scan_file(file) != True):
        return False
    return True # returns true if no extensions, indicating it is a dockerfile and passes scan

def scan_file(file_path):
    print(f"[DEBUG] Starting scan of file: {file_path}")
    try:
        # check if clamscan is available
        version_check = subprocess.run(
            ['clamscan', '--version'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=20
        )
        print(f"[DEBUG] ClamAV version: {version_check.stdout.strip()}")
        
        # creates the clam scan command
        command = ['clamscan', '--no-summary', '--bell', str(file_path)]
        print(f"[DEBUG] Executing command: {' '.join(command)}")
        
        result = subprocess.run( # runs the command and captures the output
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120
        )
        
        print(f"[DEBUG] Return code: {result.returncode}")
        print(f"[DEBUG] stdout: {result.stdout}")
        print(f"[DEBUG] stderr: {result.stderr}")
        
        if result.returncode == 0: # all possiblities of return codes are handled here
            print("[DEBUG] Scan completed successfully - no threats found")
            return True, "File clean"
        elif result.returncode == 1:
            print(f"[DEBUG] Threat detected: {result.stdout}")
            return False, f"Infected: {result.stdout}"
        else:
            error_msg = result.stderr or f"Unknown error (code {result.returncode})"
            print(f"[DEBUG] Scan failed with error: {error_msg}")
            return False, error_msg
            
    except subprocess.TimeoutExpired as te: # handles all errors that occur during the scan
        print(f"[DEBUG] Scan timed out after {te.timeout} seconds")
        return False, "Scan timed out"
    except FileNotFoundError:
        print("[DEBUG] Error: ClamAV not installed or not in PATH")
        return False, "ClamAV antivirus is not installed"
    except Exception as e:
        print(f"[DEBUG] Unexpected error: {str(e)}")
        return False, f"Scan error: {str(e)}"
    
def build_docker_image(build_path, image_name):
    client = docker.from_env()
    try:
        image, build_logs = client.images.build( # build the image
            path=build_path, # use the directory as the build context
            dockerfile='Dockerfile', # look for Dockerfile in this path
            tag=image_name,
            rm=True # clean up after build
        )
        for log in build_logs:
            print(log)
        return image, None
    except Exception as e:
        return None, str(e)

def scan_image_with_trivy(image_name):
    try:
        result = subprocess.run(
            ['docker', 'run', '--rm', '-v', '/var/run/docker.sock:/var/run/docker.sock', 'aquasec/trivy', 'image', '--scanners', 'vuln', '--format', 'cyclonedx', image_name], # runs trivy scan on the image, scanning for vulnerabilities
            capture_output=True,
            text=True,
            timeout=600 # 10 minutes
        )
        if result.returncode != 0: # checks if trivy scan was successful
            return None, f"Trivy failed: {result.stderr}"
        return json.loads(result.stdout), None
    except subprocess.TimeoutExpired:
        return None, "Trivy scan timed out after 10 minutes"
    except Exception as e:
        return None, f"Error: {str(e)}"



def generate_sbom_with_syft(image_name):
    try:
        result = subprocess.run(
            ['docker', 'run', '--rm','-v', '/var/run/docker.sock:/var/run/docker.sock', 'anchore/syft', image_name, '-o', 'cyclonedx-json'], # runs syft command to generate sbom in cyclonedx format
            capture_output=True,
            text=True,
            timeout=300
        )
        print(f"Syft return code: {result.returncode}")
        print(f"Syft stdout: {result.stdout}")
        print(f"Syft stderr: {result.stderr}")
        if result.returncode != 0: # checks if syft command was successful
            return None, f"Syft failed with return code {result.returncode}: {result.stderr}"
        return json.loads(result.stdout), None
    except json.JSONDecodeError as e:
        return None, f"Failed to parse Syft output: {str(e)}. Output: {result.stdout}"
    except Exception as e:
        return None, str(e)
    

@app.route('/')
def index():
    return render_template('index.html') # renders default page

@app.route('/upload', methods=['POST'])
def upload():
    uploaded_file = request.files.get('file')
    if uploaded_file:
        # create uploads directory if it doesn't exist
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        
        # Save the file to a temporary location
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(uploaded_file.filename))
        uploaded_file.save(temp_path)
        
        try:
            # scan the saved file
            scan_result, scan_message = scan_file(temp_path)
            if not scan_result:
                os.remove(temp_path)  # clean up if scan fails
                return f"File scan failed: {scan_message}"
            
            # read the contents after scanning
            with open(temp_path, 'r') as f:
                file_text = f.read()
            
            # parse the dockerfile using dockerfile-parse
            parser = DockerfileParser(fileobj=io.StringIO(file_text))
            instructions = parser.structure

            # array to store all found technologies
            technologies = []

            for instr in instructions:
                inst = instr['instruction'].upper()
                value = instr['value']
                if inst == 'FROM':
                    tech, version = parse_base_image(value) # extract base image and version
                    # skip if the tech name starts with '$'
                    if tech.startswith('$'):
                        continue
                    technologies.append({'technology': tech, 'version': version}) # append to the technologies array
                elif inst == 'RUN':
                    segments = re.split(r'&&|;', value) # split command into segements
                    for segment in segments:
                        segment = segment.strip()
                        if not segment:
                            continue
                        # checkk for apt-get install commands and extract all packages
                        if 'apt-get install' in segment: 
                            apt_match = re.search(r'apt-get\s+install\s+-y\s+(.*)', segment, re.IGNORECASE)
                            if apt_match:
                                packages_str = apt_match.group(1)
                                apt_pkgs = parse_apt_packages(packages_str)
                                for pkg in apt_pkgs:
                                    # Skip if package name starts with '$'
                                    if pkg[0].startswith('$'):
                                        continue
                                    technologies.append({'technology': pkg[0], 'version': pkg[1]})
                        # check for apk add commands and extract all packages
                        elif 'apk' in segment:
                            apk_match = re.search(r'apk\s+(?:(?:-\S+|--\S+)\s+)*add\s+(.*)', segment, re.IGNORECASE)
                            if apk_match:
                                packages_str = apk_match.group(1)
                                apk_pkgs = parse_apt_packages(packages_str)
                                for pkg in apk_pkgs:
                                    if pkg[0].startswith('$'):
                                        continue
                                    technologies.append({'technology': pkg[0], 'version': pkg[1]})
                        # check for pip install commands and extract all packages
                        elif 'pip install' in segment:
                            pip_match = re.search(r'pip\s+install\s+(.*)', segment, re.IGNORECASE)
                            if pip_match:
                                packages_str = pip_match.group(1)
                                pip_pkgs = parse_pip_packages(packages_str)
                                for pkg in pip_pkgs:
                                    if pkg[0].startswith('$'):
                                        continue
                                    technologies.append({'technology': pkg[0], 'version': pkg[1]})

            tech_version_list = []
            for tech in technologies:
                version = tech['version']
                if ',' in version: # if range is provided, use upper bound
                    upper_bound = version.split(',')[-1].strip()
                    upper_bound = re.sub(r'^[^0-9\.]+', '', upper_bound)
                    version = upper_bound
                tech_version_list.append(f"{tech['technology'].lower()}:{version}")

            cpe_array = search_cpe(tech_version_list, api_key) # search for cpes using processed technology list
            cve_array = search_cves(cpe_array, api_key) # search for cves using the cpes found

            formatted_lines = [] 
            for item in cve_array: # format cves
                parts = item.split(":", 1)
                if len(parts) == 2:
                    formatted_line = f"{parts[0].strip()}: {parts[1].strip()}"
                else:
                    formatted_line = item
                formatted_lines.append(formatted_line)

            components = []
            for item in cve_array: # prepare components for sbom generation
                cve_id, cve_desc = item.split(":", 1)
                components.append({"id": cve_id, "desc": cve_desc.strip()})
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

@app.route('/upload_live', methods=['POST'])
def upload_live():
    uploaded_file = request.files.get('file')
    if uploaded_file:
        # create uploads directory if it doesn't exist
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        
        # save the file to a temporary location
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(uploaded_file.filename))
        uploaded_file.save(temp_path)
        
        try:
            # scan the saved file
            scan_result, scan_message = scan_file(temp_path)
            if not scan_result:
                os.remove(temp_path) # clean up if scan fails
                return f"File scan failed: {scan_message}"
            
            # read Dockerfile content
            with open(temp_path, 'r') as f:
                file_text = f.read()
            
            image_analysis = {} # dictionary to hold image abalysis results
            with tempfile.TemporaryDirectory() as tmpdir: # creates temp directory for docker build context
                dockerfile_path = os.path.join(tmpdir, 'Dockerfile') # create a Dockerfile in that direcrtory and copy uploaded file contents to it
                with open(dockerfile_path, 'w') as f:
                    f.write(file_text)
                
                image_name = f"live-analysis-image:{time.time()}" # generate a unique image name using current time
                image, error = build_docker_image(tmpdir, image_name) # build docker image
                
                if error:
                    image_analysis['build_error'] = error # if build fails, add error to image analysis
                else:
                    trivy_results, trivy_error = scan_image_with_trivy(image_name) # if build was successful run trivy scan on the image
                    image_analysis['trivy'] = trivy_results if trivy_results else trivy_error
                    
                    syft_results, syft_error = generate_sbom_with_syft(image_name) # if build was succesful run syft scan on the image
                    image_analysis['syft'] = syft_results if syft_results else syft_error
                    
                    client = docker.from_env()
                    client.images.remove(image_name, force=True) # remove the image after analysis

            os.remove(temp_path)
            return render_template('results_live.html', # render results page with image analysis results
                                dockerfile_content=file_text,
                                image_analysis=image_analysis)

        except Exception as e:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            return f"Error processing file: {str(e)}"
    
    return "No file uploaded for live analysis."

@app.route('/download_sbom_static', methods=['POST'])
def download_sbom_static():
    sbom_data = request.form.get('sbom_data_static') # retrieve sbom data from the form
    if sbom_data:
        # use temporary file instead of memory
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp:
            tmp.write(sbom_data)
            tmp.flush()
            
        return send_file( # send file to the user for download
            tmp.name,
            mimetype='application/json',
            as_attachment=True,
            download_name='sbom_static.json',
            conditional=True
        )
    return "No SBOM data provided", 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
