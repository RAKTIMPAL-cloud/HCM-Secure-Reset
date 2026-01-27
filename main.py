import streamlit as st
import requests
import base64
import xml.etree.ElementTree as ET
import pandas as pd
from io import StringIO
import json
import secrets
import string

# --- App Configuration ---
st.set_page_config(page_title="Oracle HCM SecureReset Pro", layout="wide")
st.title("🔐 Oracle HCM SecureReset Pro")

# --- UI Layout: Connection & Inputs ---
col1, col2 = st.columns([1, 1])

with col1:
    st.subheader("🌐 Connection Details")
    env_url = st.text_input("Environment URL", "https://iavnqy-dev2.fa.ocs.oraclecloud.com")
    username = st.text_input("Admin Username")
    password = st.text_input("Admin Password", type="password")

with col2:
    st.subheader("👥 Target Usernames")
    user_input = st.text_area(
        "Enter Usernames (comma separated)", 
        placeholder="user1@example.com, user2@example.com",
        height=150
    )

# --- Logic Functions ---

def generate_secure_password(length=12):
    """Generates a secure password meeting Oracle standard policy."""
    alphabet = string.ascii_letters + string.digits + "!#$%"
    pwd = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice("!#$%")
    ]
    pwd += [secrets.choice(alphabet) for _ in range(length - 4)]
    secrets.SystemRandom().shuffle(pwd)
    return "".join(pwd)

def fetch_guids_soap(env_url, admin_user, admin_pwd, user_list_str):
    """Calls BIP SOAP service to resolve Usernames to GUIDs."""
    full_url = env_url.rstrip("/") + "/xmlpserver/services/ExternalReportWSSService"
    report_path = "/Custom/Human Capital Management/PASSWORD/User_GUID_Report.xdo"
    
    clean_user_list = ",".join([u.strip() for u in user_list_str.split(",") if u.strip()])

    soap_request = f"""
    <soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:pub="http://xmlns.oracle.com/oxp/service/PublicReportService">
       <soap:Header/>
       <soap:Body>
          <pub:runReport>
             <pub:reportRequest>
                <pub:attributeFormat>csv</pub:attributeFormat>
                <pub:reportAbsolutePath>{report_path}</pub:reportAbsolutePath>
                <pub:parameterNameValues>
                    <pub:item>
                        <pub:name>p_usernames</pub:name>
                        <pub:values>
                            <pub:item>{clean_user_list}</pub:item>
                        </pub:values>
                    </pub:item>
                </pub:parameterNameValues>
                <pub:sizeOfDataChunkDownload>-1</pub:sizeOfDataChunkDownload>
             </pub:reportRequest>
          </pub:runReport>
       </soap:Body>
    </soap:Envelope>
    """
    
    auth_header = base64.b64encode(f"{admin_user}:{admin_pwd}".encode()).decode()
    headers = {
        "Content-Type": "application/soap+xml; charset=utf-8",
        "Authorization": f"Basic {auth_header}"
    }

    try:
        response = requests.post(full_url, data=soap_request, headers=headers)
        if response.status_code == 200:
            root = ET.fromstring(response.content)
            ns = {'ns': 'http://xmlns.oracle.com/oxp/service/PublicReportService'}
            report_bytes = root.find('.//ns:reportBytes', ns)
            if report_bytes is not None and report_bytes.text:
                return base64.b64decode(report_bytes.text).decode("utf-8")
        return None
    except Exception:
        return None

def call_scim_bulk_api(env_url, admin_user, admin_pwd, guid_df):
    """Executes Bulk PATCH via SCIM REST API."""
    scim_url = env_url.rstrip("/") + "/hcmRestApi/scim/Bulk"
    new_password = generate_secure_password()
    
    operations = []
    for _, row in guid_df.iterrows():
        operations.append({
            "method": "PATCH",
            "path": f"/Users/{row['USER_GUID']}",
            "bulkId": str(row['USERNAME']),
            "data": {
                "schemas": ["urn:scim:schemas:core:2.0:User"],
                "password": new_password
            }
        })

    payload = {"Operations": operations}
    response = requests.post(
        scim_url, 
        json=payload, 
        auth=(admin_user, admin_pwd),
        headers={"Content-Type": "application/json"}
    )
    return response, new_password

# --- Main Logic ---

if st.button("🚀 Execute Bulk Password Reset"):
    if not (username and password and user_input):
        st.warning("⚠️ Please provide all credentials and target usernames.")
    else:
        with st.spinner("🔍 Step 1: Querying Oracle for User GUIDs..."):
            csv_data = fetch_guids_soap(env_url, username, password, user_input)
            
            if csv_data:
                df = pd.read_csv(StringIO(csv_data))
                df.columns = [c.strip().upper() for c in df.columns]
                
                if 'USER_GUID' in df.columns and not df.empty:
                    st.info(f"✅ Found {len(df)} users in Fusion.")
                    
                    with st.spinner("⚡ Step 2: Resetting Passwords via SCIM Bulk API..."):
                        res, common_pwd = call_scim_bulk_api(env_url, username, password, df)
                        
                        if res.status_code in [200, 201]:
                            st.success(f"🎊 Bulk Reset Complete! Temporary Password: `{common_pwd}`")
                            
                            results = res.json().get("Operations", [])
                            status_rows = []
                            for op in results:
                                status_rows.append({
                                    "Username": op.get("bulkId"),
                                    "HTTP Status": op.get("status", {}).get("code"),
                                    "Outcome": "✅ Success" if str(op.get("status", {}).get("code")).startswith("2") else "❌ Failed"
                                })
                            st.table(pd.DataFrame(status_rows))
                        
                        else:
                            # friendly error mapping
                            error_messages = {
                                401: "🚫 **Unauthorized**: Invalid Admin Username or Password.",
                                403: "🛑 **Forbidden**: You do not have the required roles (Security Console Administrator or Identity Domain Admin) to perform this action.",
                                404: "🌐 **Not Found**: The SCIM REST endpoint was not found at this URL.",
                                500: "⚙️ **Internal Server Error**: Oracle Fusion had a problem processing this request."
                            }
                            friendly_err = error_messages.get(res.status_code, f"⚠️ **Request Failed (Status: {res.status_code})**")
                            st.error(friendly_err)
                else:
                    st.error("❌ No matching users found in PER_USERS. Please check the usernames.")
            else:
                st.error("❌ Could not connect to the BIP report. Verify the report path and credentials.")

# Footer
st.markdown("""
<hr style="margin-top: 50px;">
<div style='text-align: center; color: yellow; font-size: 0.85em;'>
    <p>App has been developed by <strong>Raktim Pal</strong></p>
    <p>© 2026 Raktim Pal. All rights reserved.</p>
</div>
""", unsafe_allow_html=True)
