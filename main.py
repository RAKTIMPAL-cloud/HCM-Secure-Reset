import streamlit as st
import requests
import pandas as pd
import base64
import xml.etree.ElementTree as ET
from io import StringIO, BytesIO
import string
import secrets

# --- App Configuration ---
st.set_page_config(page_title="Oracle HCM Pro: Bulk Creator", layout="wide")
st.title("👤 Oracle HCM: Smart User & Role Management")

# --- Functions ---

def generate_secure_password(length=12):
    alphabet = string.ascii_letters + string.digits + "!#$%"
    pwd = [secrets.choice(string.ascii_uppercase), secrets.choice(string.ascii_lowercase),
           secrets.choice(string.digits), secrets.choice("!#$%")]
    pwd += [secrets.choice(alphabet) for _ in range(length - 4)]
    secrets.SystemRandom().shuffle(pwd)
    return "".join(pwd)

def fetch_guids_via_soap(env_url, admin_user, admin_pwd, usernames, roles):
    full_url = env_url.rstrip("/") + "/xmlpserver/services/ExternalReportWSSService"
    report_path = "/Custom/Human Capital Management/PASSWORD/User_Role_GUID_Report.xdo"
    
    user_str = ",".join(filter(None, set(usernames)))
    role_str = ",".join(filter(None, set(roles)))

    soap_request = f"""
    <soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:pub="http://xmlns.oracle.com/oxp/service/PublicReportService">
       <soap:Body>
          <pub:runReport>
             <pub:reportRequest>
                <pub:attributeFormat>csv</pub:attributeFormat>
                <pub:reportAbsolutePath>{report_path}</pub:reportAbsolutePath>
                <pub:parameterNameValues>
                    <pub:item><pub:name>p_usernames</pub:name><pub:values><pub:item>{user_str}</pub:item></pub:values></pub:item>
                    <pub:item><pub:name>p_roles</pub:name><pub:values><pub:item>{role_str}</pub:item></pub:values></pub:item>
                </pub:parameterNameValues>
                <pub:sizeOfDataChunkDownload>-1</pub:sizeOfDataChunkDownload>
             </pub:reportRequest>
          </pub:runReport>
       </soap:Body>
    </soap:Envelope>"""
    
    auth = base64.b64encode(f"{admin_user}:{admin_pwd}".encode()).decode()
    headers = {"Content-Type": "application/soap+xml; charset=utf-8", "Authorization": f"Basic {auth}"}

    try:
        res = requests.post(full_url, data=soap_request, headers=headers, timeout=30)
        root = ET.fromstring(res.content)
        ns = {'ns': 'http://xmlns.oracle.com/oxp/service/PublicReportService'}
        report_bytes = root.find('.//ns:reportBytes', ns)
        if report_bytes is not None and report_bytes.text:
            return base64.b64decode(report_bytes.text).decode("utf-8")
        return None
    except:
        return None

def execute_scim_bulk(env_url, admin_user, admin_pwd, operations):
    scim_url = env_url.rstrip("/") + "/hcmRestApi/scim/Bulk"
    payload = {
        "schemas": ["urn:scim:schemas:core:2.0:BulkRequest"],
        "failOnErrors": 1,
        "Operations": operations
    }
    return requests.post(scim_url, json=payload, auth=(admin_user, admin_pwd))

# --- UI ---
col1, col2 = st.columns(2)
with col1:
    st.subheader("🌐 Connection")
    env_url = st.text_input("URL", "https://iavnqy-dev2.fa.ocs.oraclecloud.com")
    username = st.text_input("Admin Username")
    password = st.text_input("Admin Password", type="password")

with col2:
    st.subheader("📁 Data")
    template_df = pd.DataFrame(columns=['USER NAME', 'FIRST NAME', 'LAST NAME', 'WORK EMAIL', 'ROLE TO BE ASSIGNED'])
    tmp_buff = BytesIO()
    with pd.ExcelWriter(tmp_buff, engine='xlsxwriter') as writer:
        template_df.to_excel(writer, index=False)
    st.download_button("📥 Template", tmp_buff.getvalue(), "Template.xlsx")
    uploaded_file = st.file_uploader("Upload Excel", type=["xlsx"])

# --- Processing ---
if st.button("🚀 Process Bulk Operations"):
    if not (username and password and uploaded_file):
        st.warning("Please fill all details.")
    else:
        df = pd.read_excel(uploaded_file)
        df.columns = [c.strip().upper() for c in df.columns]
        common_pwd = generate_secure_password()
        
        # 1. PHASE 1: CREATE USERS (Unique only)
        unique_users_df = df.drop_duplicates(subset=['USER NAME'])
        user_ops = []
        for _, row in unique_users_df.iterrows():
            user_ops.append({
                "method": "POST", "path": "/Users", "bulkId": str(row['USER NAME']),
                "data": {
                    "schemas": ["urn:scim:schemas:core:2.0:User"],
                    "userName": str(row['USER NAME']),
                    "name": {"familyName": str(row['LAST NAME']), "givenName": str(row['FIRST NAME'])},
                    "emails": [{"primary": True, "value": str(row['WORK EMAIL']), "type": "W"}],
                    "active": True, "password": common_pwd
                }
            })

        user_status_results = {}
        with st.spinner("⏳ Step 1: Processing User Creation..."):
            u_res = execute_scim_bulk(env_url, username, password, user_ops)
            if u_res.status_code in [200, 201]:
                for op in u_res.json().get("Operations", []):
                    code = str(op.get("status", {}).get("code", ""))
                    u_id = op.get("bulkId")
                    if code == "201": user_status_results[u_id] = "✅ User Created Successfully"
                    elif code == "409": user_status_results[u_id] = "ℹ️ User Already Exists"
                    else: user_status_results[u_id] = f"❌ Error: {op.get('response', {}).get('detail', 'Failed')}"

        # 2. PHASE 2: RESOLVE GUIDs
        with st.spinner("⏳ Step 2: Fetching GUIDs..."):
            csv_data = fetch_guids_via_soap(env_url, username, password, df['USER NAME'].tolist(), df['ROLE TO BE ASSIGNED'].tolist())
            
        if csv_data:
            g_df = pd.read_csv(StringIO(csv_data))
            g_df.columns = [c.strip().upper() for c in g_df.columns]
            u_map = g_df[g_df['TYPE'] == 'USER'].set_index('SEARCH_KEY')['GUID'].to_dict()
            r_map = g_df[g_df['TYPE'] == 'ROLE'].set_index('SEARCH_KEY')['GUID'].to_dict()

            # 3. PHASE 3: ASSIGN ROLES
            role_ops = []
            tracking_list = []
            for _, row in df.iterrows():
                u_name, r_name = str(row['USER NAME']), str(row['ROLE TO BE ASSIGNED'])
                u_guid, r_guid = u_map.get(u_name), r_map.get(r_name)
                
                b_id = f"assign_{u_name}_{secrets.token_hex(3)}"
                if u_guid and r_guid:
                    role_ops.append({
                        "method": "PATCH", "path": f"/Roles/{r_guid}", "bulkId": b_id,
                        "data": {"members": [{"value": u_guid, "operation": "ADD"}]}
                    })
                    tracking_list.append({"USER": u_name, "ROLE": r_name, "USER_STATUS": user_status_results.get(u_name, "N/A"), "BULK_ID": b_id})
                else:
                    tracking_list.append({"USER": u_name, "ROLE": r_name, "USER_STATUS": user_status_results.get(u_name, "N/A"), "ROLE_STATUS": "❌ Missing GUID", "BULK_ID": None})

            if role_ops:
                with st.spinner("⏳ Step 3: Assigning Roles..."):
                    r_res = execute_scim_bulk(env_url, username, password, role_ops)
                    r_results = {op.get("bulkId"): str(op.get("status", {}).get("code", "")) for op in r_res.json().get("Operations", [])}
                    
                    for item in tracking_list:
                        if item["BULK_ID"] in r_results:
                            code = r_results[item["BULK_ID"]]
                            if code.startswith("2"): item["ROLE_STATUS"] = "✅ Role Assigned Successfully"
                            elif code == "409": item["ROLE_STATUS"] = "ℹ️ Role Already Assigned"
                            else: item["ROLE_STATUS"] = "❌ Assignment Failed"
            
            # --- FINAL SUMMARY ---
            st.divider()
            st.subheader("📋 Final Execution Summary")
            st.info(f"🔑 Shared Password for new users: `{common_pwd}`")
            
            final_df = pd.DataFrame(tracking_list).drop(columns=['BULK_ID'])
            st.table(final_df)
        else:
            st.error("🚨 Error: Could not retrieve GUIDs from Oracle report. Please check the report path and permissions.")

st.markdown("<hr><center>Developed by <b>Raktim Pal</b></center>", unsafe_allow_html=True)
