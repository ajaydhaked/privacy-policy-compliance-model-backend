import os
import sys
import json
import time
import hashlib

from flask import Flask, request, jsonify
from flask_cors import CORS
from diskcache import Cache

current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from dotenv import load_dotenv
load_dotenv(os.path.join(current_dir, ".env"))

model_dir = os.path.join(current_dir, 'model')

from src.utils import read_json, read_file, log
from src.rulesEvaluator import RulesEvaluator
from src.createAllAccessRequests import CreateAllAccessRequest
from src.violationAnalyzer import ViolationAnalyzer

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})




def make_key(content, url="", title=""):
    content_hash = hashlib.sha256(content.encode()).hexdigest()
    return f"{url}:{title}:{content_hash}"

def get_cached_result(content, url="", title=""):
    return cache.get(make_key(content, url, title))

def save_result(content, result, url="", title=""):
    key = make_key(content, url, title)
    cache[key] = result
    cache.expire(key, 60 * 60 * 24) # 24 hours

try:
    cache = Cache(os.path.join(current_dir, ".cache"))
    print("Small Cache Db started")
except Exception as e:
    print(f"Warning: Cache initialization failed: {e}")
    cache = None

create_all_access_request = None

try:
    ALL_ATTRIBUTES_FILE_PATH = os.path.join(current_dir, "all_attributes_list.json")
    ATTRIBUTE_INFERENCE_PROMPT_TEMPLATE_PATH = os.path.join(
        current_dir, "prompts", "attribute_inference_llm_prompt.txt"
    )
    
    all_attributes = read_json(ALL_ATTRIBUTES_FILE_PATH)
    attribute_inference_prompt_template = read_file(ATTRIBUTE_INFERENCE_PROMPT_TEMPLATE_PATH)
    
    create_all_access_request = CreateAllAccessRequest(
        all_attributes,
        attribute_inference_prompt_template
    )
    
    os.makedirs(os.path.join(current_dir, "backend_logs"), exist_ok=True)
    os.makedirs(os.path.join(current_dir, "backend_outputs"), exist_ok=True)

    print("CreateAllAccessRequest initialized successfully")

except Exception as e:
    import traceback
    print(f"Warning: Initialization error during app startup: {e}")
    traceback.print_exc()



@app.route("/analyze", methods=["POST"])
def analyze_policy():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"detail": "Invalid or missing JSON body"}), 400

        content = data.get("content", "")
        url = data.get("url", "")
        title = data.get("title", "")

        if not content or not content.strip():
            return jsonify({"detail": "Policy text is empty"}), 400

        company_name = title if title else "Unknown"
        safe_name = "".join([c if c.isalnum() else "_" for c in company_name])[:20]
        log_file_name = os.path.join(current_dir, "backend_logs", f"{safe_name}_{time.strftime('%Y%m%d_%H%M%S')}.txt")

        log(title, heading="TITLE", file_path=log_file_name)
        log(url, heading="URL", file_path=log_file_name)
        log(content, heading="RECEIVED PRIVACY POLICY", file_path=log_file_name)

        cached_result = get_cached_result(content, url, title) if cache else None
        if cached_result:
            log("Using cached result", heading="CACHED RESULT", file_path=log_file_name)
            return jsonify(cached_result)

        violation_analyzer = ViolationAnalyzer()

        rules_evaluator = RulesEvaluator()

        all_access_requests = create_all_access_request.form_all_access_request_for_privacy_policy(
            content,
            log_file_path=log_file_name
        )

        total_requests = len(all_access_requests)
        compliant_requests = 0
        last_access_request = None

        for req_idx, access_request in enumerate(all_access_requests, start=1):
            last_access_request = access_request
            rules_evaluator.evaluate_all_rules(access_request)

            allowed = access_request.get("allow_data_processing") == "true"

            log(
                json.dumps(access_request.get_attributes(), indent=2),
                heading=f"CHECKING ACCESS_REQUEST {req_idx}",
                file_path=log_file_name
            )
            log(
                rules_evaluator.evaluation_logs,
                heading=f"EVALUATION LOGS {req_idx}",
                file_path=log_file_name
            )

            if allowed:
                compliant_requests += 1
                log(
                    "DATA PROCESSING IS ALLOWED",
                    heading="DATA PROCESSING ALLOWED",
                    file_path=log_file_name
                )

        policy_compliant = compliant_requests > 0
        reasoning = (
            f"Policy compliance check completed. "
            f"{compliant_requests} out of {total_requests} access requests "
            f"were found to be compliant with the rules."
        )

        violations = violation_analyzer.get_violations(last_access_request) if last_access_request else {}
        violations_list = violation_analyzer.get_violations_list(violations)

        log(json.dumps(violations, indent=2), heading="VIOLATIONS", file_path=log_file_name)
        log(violations_list, heading="FORMATTED VIOLATIONS", file_path=log_file_name)
        log(reasoning, heading="REASONING", file_path=log_file_name)

        print(violations_list)

        result = {
            "status": "COMPLIANT" if policy_compliant else "NON_COMPLIANT",
            "violations": violations_list
        }

        if cache:
            save_result(content, result, url, title)

        return jsonify(result)

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"detail": f"Analysis failed: {str(e)}"}), 500


@app.route("/", methods=["GET"])
def read_root():
    return jsonify({"status": "Privacy Policy Backend is running"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)