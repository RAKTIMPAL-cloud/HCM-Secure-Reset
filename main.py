import streamlit as st
import requests
import pandas as pd
import base64
import xml.etree.ElementTree as ET
from io import StringIO, BytesIO
import secrets

# --- App Configuration ---
st.set_page_config(page_title="Oracle HCM Smart Manager", layout="wide")
st.title("👤 Oracle HCM: Bulk User & Role Processor")

# --- Logic Functions ---

def fetch_guids_via_soap(env_url, admin_user, admin_pwd, usernames, roles):
    full_url = env_url.rstrip("/") + "/xmlpserver/services/ExternalReportWSSService"
    report_path = "/Custom/Human Capital Management/PASSWORD/User_Role_GUID_Report.xdo"
    
    # Cleaning data for SQL compatibility
    user_str = ",".join(filter(None, set([str(u).strip() for u in usernames])))
    role_str = ",".join(filter(None, set([str(r).strip() for r in roles])))

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
             </pub:reportRequest>
          </pub:runReport>
       </soap:Body>
    </soap:Envelope>"""
    
    auth = base64.b64encode(f"{admin_user}:{admin_pwd}".encode()).decode()
    headers = {"Content-Type": "application/soap+xml; charset=utf-8", "Authorization": f"Basic {auth}"}

    try:
        res = requests.post(full_url, data=soap_request, headers=headers, timeout=45)
        if res.status_code != 200:
            st.error(f"❌ SOAP HTTP Error {res.status_code}: {res.text[:200]}")
            return None
            
        root = ET.fromstring(res.content)
        ns = {'ns': 'http://xmlns.oracle.com/oxp/service/PublicReportService'}
        report_bytes = root.find('.//ns:reportBytes', ns)
        
        if report_bytes is not None and report_bytes.text:
            return base64.b64decode(report_bytes.text).decode("utf-8")
        else:
            st.warning("⚠️ Report returned empty. Ensure usernames/roles match Oracle case-sensitivity.")
            return None
    except Exception as e:
        st.error(f"🚨 Connection Error: {str(e)}")
        return None

def execute_scim_bulk(env_url, admin_user, admin_pwd, operations):
    scim_url = env_url.rstrip("/") + "/hcmRestApi/scim/Bulk"
    payload = {"schemas": ["urn:scim:schemas:core:2.0:BulkRequest"], "failOnErrors": 1, "Operations": operations}
    
    response = requests.post(scim_url, json=payload, auth=(admin_user, admin_pwd))
    
    # Handle Global API Errors
    if response.status_code == 401: return "ERROR: 401 Unauthorized - Check Credentials"
    if response.status_code == 403: return "ERROR: 403 Forbidden - Check URL/Permissions"
    if response.status_code == 400: return "ERROR: 400 Bad Request - Payload Error"
    
    return response

# --- UI Layout ---
col1, col2 = st.columns(2)
with col1:
    st.subheader("🌐 Connection Settings")
    env_url = st.text_input("Oracle URL", "https://iavnqy-dev2.fa.ocs.oraclecloud.com")
    admin_user = st.text_input("Admin Username")
    admin_pwd = st.text_input("Admin Password", type="password")

with col2:
    st.subheader("📁 Data Source")
    uploaded_file = st.file_uploader("Upload User/Role Excel", type=["xlsx"])

if st.button("🚀 Execute Smart Bulk Process"):
    if not (admin_user and admin_pwd and uploaded_file):
        st.warning("Please provide all required inputs.")
    else:
        df = pd.read_excel(uploaded_file)
        df.columns = [c.strip().upper() for c in df.columns]
        
        # 1. PHASE 1: CREATE USERS
        unique_users = df.drop_duplicates(subset=['USER NAME'])
        user_ops = []
        for _, row in unique_users.iterrows():
            user_ops.append({
                "method": "POST", "path": "/Users", "bulkId": str(row['USER NAME']),
                "data": {
                    "schemas": ["urn:scim:schemas:core:2.0:User"],
                    "userName": str(row['USER NAME']).strip(),
                    "name": {"familyName": str(row['LAST NAME']), "givenName": str(row['FIRST NAME'])},
                    "emails": [{"primary": True, "value": str(row['WORK EMAIL']), "type": "W"}],
                    "active": True, "password": "Welcome@123" # Shared starter pwd
                }
            })

        user_status_results = {}
        with st.spinner("⏳ Processing User Creation..."):
            u_res = execute_scim_bulk(env_url, admin_user, admin_pwd, user_ops)
            
            if isinstance(u_res, str): # Caught a 401/403/400
                st.error(u_res)
            else:
                for op in u_res.json().get("Operations", []):
                    code = str(op.get("status", {}).get("code", ""))
                    u_id = op.get("bulkId")
                    user_status_results[u_id] = "✅ Created" if code == "201" else "ℹ️ Already Exists" if code == "409" else f"❌ {code}"

        # 2. PHASE 2: RESOLVE GUIDs
        with st.spinner("⏳ Resolving GUIDs from BIP..."):
            csv_data = fetch_guids_via_soap(env_url, admin_user, admin_pwd, df['USER NAME'].tolist(), df['ROLE TO BE ASSIGNED'].tolist())
            
        if csv_data:
            g_df = pd.read_csv(StringIO(csv_data))
            g_df.columns = [c.strip().upper() for c in g_df.columns]
            u_map = g_df[g_df['TYPE'] == 'USER'].set_index('SEARCH_KEY')['GUID'].to_dict()
            r_map = g_df[g_df['TYPE'] == 'ROLE'].set_index('SEARCH_KEY')['GUID'].to_dict()

            # 3. PHASE 3: ASSIGN ROLES
            role_ops = []
            tracking_list = []
            for _, row in df.iterrows():
                u_name, r_name = str(row['USER NAME']).strip(), str(row['ROLE TO BE ASSIGNED']).strip()
                u_guid, r_guid = u_map.get(u_name), r_map.get(r_name)
                
                b_id = f"r_{secrets.token_hex(4)}"
                if u_guid and r_guid:
                    role_ops.append({
                        "method": "PATCH", "path": f"/Roles/{r_guid}", "bulkId": b_id,
                        "data": {"members": [{"value": u_guid, "operation": "ADD"}]}
                    })
                    tracking_list.append({"USER": u_name, "ROLE": r_name, "USER_STATUS": user_status_results.get(u_name, "N/A"), "B_ID": b_id})
                else:
                    tracking_list.append({"USER": u_name, "ROLE": r_name, "USER_STATUS": user_status_results.get(u_name, "N/A"), "ROLE_STATUS": "❌ GUID Missing", "B_ID": None})

            if role_ops:
                with st.spinner("⏳ Assigning Roles..."):
                    r_res = execute_scim_bulk(env_url, admin_user, admin_pwd, role_ops)
                    r_data = {op.get("bulkId"): str(op.get("status", {}).get("code", "")) for op in r_res.json().get("Operations", [])}
                    
                    for item in tracking_list:
                        if item["B_ID"] in r_data:
                            # As per your sample, 204 is the only success code for Roles
                            item["ROLE_STATUS"] = "✅ Processed" if r_data[item["B_ID"]] == "204" else f"❌ Error {r_data[item['B_ID']]}"
            
            st.divider()
            st.subheader("📋 Execution Summary")
            st.table(pd.DataFrame(tracking_list).drop(columns=['B_ID']))
        else:
            st.info("💡 Tip: Try running the BIP report manually with these parameters to see if it returns data.")

st.markdown("<hr><center>Developed by <b>Raktim Pal</b></center>", unsafe_allow_html=True)
