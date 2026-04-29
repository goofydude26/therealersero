import tempfile
import os
import logging
from androguard.core.bytecodes.apk import APK

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

HIGH_RISK_PERMISSIONS = {
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.READ_PHONE_STATE",
    "android.permission.SYSTEM_ALERT_WINDOW"
}

MEDIUM_RISK_PERMISSIONS = {
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.INTERNET",
    "android.permission.BLUETOOTH",
    "android.permission.NFC",
    "android.permission.VIBRATE",
    "android.permission.WAKE_LOCK"
}

def calculate_risk(permissions):
    score = 0
    issues = []
    
    if not permissions:
        return {"level": "LOW", "score": 0, "issues": [{"type": "info", "message": "No permissions found."}]}
        
    for perm in permissions:
        if perm in HIGH_RISK_PERMISSIONS:
            score += 20
            issues.append({"type": "error", "message": f"High risk permission detected: {perm.split('.')[-1]}"})
        elif perm in MEDIUM_RISK_PERMISSIONS:
            score += 5
            if perm == "android.permission.INTERNET":
                issues.append({"type": "info", "message": "Uses standard network permission (INTERNET)."})
            else:
                issues.append({"type": "warning", "message": f"Medium risk permission detected: {perm.split('.')[-1]}"})
            
    # Cap score at 100
    score = min(score, 100)
    
    if score >= 60:
        level = "HIGH"
    elif score >= 20:
        level = "MEDIUM"
    else:
        level = "LOW"
        
    if not issues:
        issues.append({"type": "success", "message": "No dangerous permissions found."})
        
    return {
        "level": level,
        "score": score,
        "issues": issues
    }

def analyze_apk(uploaded_file):
    """
    Analyzes an uploaded APK file using androguard.
    
    Args:
        uploaded_file: A Streamlit UploadedFile object containing the APK.
        
    Returns:
        dict: A dictionary containing extracted information or an error message.
    """
    # Create a temporary file to save the uploaded APK
    # Androguard works best with file paths
    temp_dir = tempfile.mkdtemp()
    temp_path = os.path.join(temp_dir, "temp.apk")
    
    try:
        # Write the uploaded bytes to the temp file
        with open(temp_path, "wb") as f:
            f.write(uploaded_file.getvalue())
            
        # Parse the APK using androguard
        logger.info(f"Analyzing APK: {uploaded_file.name}")
        apk = APK(temp_path)
        
        # Check if the APK is valid
        if not apk.is_valid_APK():
            return {"error": "The uploaded file is not a valid APK."}
            
        # Extract information
        package_name = apk.get_package()
        version_name = apk.get_androidversion_name()
        target_sdk = apk.get_target_sdk_version()
        permissions = sorted(list(permissions)) if permissions else []
        risk_analysis = calculate_risk(permissions)
        
        # Return the parsed data
        return {
            "success": True,
            "package_name": package_name if package_name else "Unknown",
            "version_name": version_name if version_name else "Unknown",
            "target_sdk": target_sdk if target_sdk else "Unknown",
            "permissions": permissions,
            "risk_analysis": risk_analysis
        }
        
    except Exception as e:
        logger.error(f"Error analyzing APK: {str(e)}")
        return {"error": f"Failed to analyze APK: {str(e)}"}
        
    finally:
        # Clean up the temporary file
        if os.path.exists(temp_path):
            os.remove(temp_path)
        if os.path.exists(temp_dir):
            os.rmdir(temp_dir)
